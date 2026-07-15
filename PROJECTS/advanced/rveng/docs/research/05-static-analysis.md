<!-- ©AngelaMos | 2026 -->
<!-- 05-static-analysis.md -->

# Static Analysis Depth Research

The M3.5 depth features that lift rveng from a hex-and-disasm viewer to a real
static reverse-engineering workbench: import resolution through the PLT, cross
references with RIP-relative operand math, control-flow-graph reconstruction,
and function discovery in stripped binaries. Every offset, opcode, and address
below is traced to the sample `gate` binary (`gcc -no-pie -fno-stack-protector
-O0`) and its stripped copy `gate_stripped` (`strip gate`), captured with
`readelf` and `objdump -M intel`. Nothing here executes a binary: PLT, GOT, and
relocation tables are inspected as data, exactly like the header and sections.

## Import resolution through the PLT

A dynamically linked call does not jump straight to libc. It jumps to a small
stub in `.plt` that reads a pointer from `.got.plt`, which the dynamic linker
fills in. To name a call the way objdump prints `call 401030 <puts@plt>`, the
engine resolves the stub back to the imported symbol.

Sections that carry the mapping, from `readelf -SW gate`:

- `.plt` PROGBITS at `0x401020`, entry size `0x10` (16 bytes).
- `.got.plt` PROGBITS at `0x403fe8`, entry size 8.
- `.rela.plt` RELA at `0x400520`, entry size `0x18` (24 bytes), 3 entries.
- `.dynsym` DYNSYM at `0x4003d0`, entry size `0x18`, its linked string table is
  `.dynstr`.

The `.plt` layout from `objdump -d -j .plt`:

```
401020 <puts@plt-0x10>:   push/jmp/nop     the PLT0 resolver stub (not an import)
401030 <puts@plt>:        ff 25 ca 2f 00 00   jmp QWORD PTR [rip+0x2fca]  -> 404000
401040 <printf@plt>:      ff 25 c2 2f 00 00   jmp QWORD PTR [rip+0x2fc2]  -> 404008
401050 <atoi@plt>:        ff 25 ba 2f 00 00   jmp QWORD PTR [rip+0x2fba]  -> 404010
```

The first `.plt` slot (`0x401020`) is the resolver trampoline (PLT0), not an
import. Real entries begin at `0x401030` and step by 16.

Resolution algorithm, robust across PIE and non-PIE:

1. For a PLT entry, decode its leading `jmp QWORD PTR [rip+disp32]` (opcode
   `ff 25`). The GOT slot it reads is `entry_addr + 6 + disp32`. For `0x401030`:
   `0x401036 + 0x2fca = 0x404000`.
2. `.rela.plt` maps each GOT slot to a dynamic symbol. Each `Elf64_Rela` is
   `{ r_offset: u64, r_info: u64, r_addend: i64 }`. The symbol index is
   `r_info >> 32`; the type is `r_info & 0xffffffff` (7 = `R_X86_64_JUMP_SLOT`).
   From `readelf -rW`:

   ```
   r_offset 0x404000  sym 2  JUMP_SLOT  puts
   r_offset 0x404008  sym 3  JUMP_SLOT  printf
   r_offset 0x404010  sym 5  JUMP_SLOT  atoi
   ```
3. Look the symbol index up in `.dynsym` (same 24-byte `Elf64_Sym` layout as
   `.symtab`, names via `.dynstr`) to get `puts`, `printf`, `atoi`.

So `0x401030 -> 0x404000 -> dynsym[2] -> puts`. A `call` whose target is a `.plt`
entry is then annotated with that name.

KAT (call-site to import, from `main` in `objdump -d`):

- `401199: call 401050` resolves to `atoi`.
- `4011a6: call 401146` is `check`, a local function, not a PLT entry.
- `4011c5: call 401040` resolves to `printf`.
- `4011d6: call 401030` resolves to `puts`.

VERIFIED, and load-bearing for the stripped module: `.plt`, `.got.plt`,
`.rela.plt`, and `.dynsym` all SURVIVE `strip`. `readelf -SW gate_stripped`
still shows them; `readelf -rW gate_stripped` still lists the three JUMP_SLOT
relocations to `puts`, `printf`, `atoi`. Stripping removes `.symtab` and
`.strtab` (local names like `check`, `main`), never the dynamic-linking tables.
A stripped binary can still name its library calls. This is a real teaching
point, not an accident.

Robustness note an adversarial check flagged: binaries built with
`-fcf-protection` (default on many modern toolchains) grow an `endbr64` and a
`.plt.sec` section, so the `jmp [rip+x]` may live in `.plt.sec` rather than
`.plt`. Resolving by decoding the stub's `jmp [rip+disp]` wherever it sits (and
matching the GOT slot against `.rela.plt`) handles both layouts; resolving by
the PLT entry's pushed relocation index does not. The engine decodes the jmp.
Our curated `-no-pie -O0` samples use the classic single `.plt`.

## RIP-relative cross references

x86-64 addresses data PC-relative. `lea rax,[rip+disp]` computes an absolute
address as `address_of_next_instruction + disp`, where the next-instruction
address is `insn.address + insn.size`. This is how a function points at a string
without a relocation in a non-PIE binary.

KAT (from `main`, `objdump -d -j .text`):

- `401173: lea rax,[rip+0xe8a]` with size 7 resolves to `0x40117a + 0xe8a =
  0x402004`, the `.rodata` string `the_flag_is_here`.
- `4011b6: lea rax,[rip+0xe58]` (size 7) resolves to `0x4011bd + 0xe58 =
  0x402015`, the `unlocked: %s` format string.
- `4011cc: lea rax,[rip+0xe50]` (size 7) resolves to `0x4011d3 + 0xe50 =
  0x402023`, the `wrong number` string.

capstone exposes the displacement on the memory operand whose base register is
RIP. The engine computes `insn.address + insn.size + disp` and, when that
address falls inside a known section, labels the reference (a `.rodata` hit is a
string; a `.text` hit is code).

Cross references are the inverse index: for a target address, the list of
instructions that reach it. Two reference kinds cover these challenges:

- control-flow refs, from `call`/`jmp`/`jcc` branch targets. Example: `check` at
  `0x401146` is referenced by `4011a6: call 401146` in `main`.
- data refs, from resolved RIP-relative operands. Example: the flag string at
  `0x402004` is referenced by `401173: lea` in `main`.

"What calls this function" and "what reads this string" are the two questions a
learner asks constantly; both are this same reverse map.

## Control-flow graph reconstruction

A basic block is a straight run of instructions with one entry and one exit: no
branch lands in the middle, no branch leaves except at the end. The standard
leader algorithm:

1. The first instruction of the function is a leader.
2. Any branch target inside the function is a leader.
3. The instruction following any conditional or unconditional jump is a leader.

A block runs from a leader up to the instruction before the next leader. `call`
does NOT end a block: it returns, so control falls through. Blocks end at
conditional jumps, unconditional jumps, and `ret`. This matches how IDA and
Ghidra draw function graphs.

KAT: `check` (`0x401146`..`0x401163`), from `objdump -d`:

```
401146 push rbp                          | B0 (entry)
401147 mov rbp,rsp                        |
40114a mov [rbp-4],edi                    |
40114d cmp [rbp-4],0x539                  |
401154 jne 40115d                         | -> ends B0
401156 mov eax,1                          | B1 (fallthrough of jne)
40115b jmp 401162                          | -> ends B1
40115d mov eax,0                          | B2 (jne taken target)
401162 pop rbp                            | B3 (jmp target, also B2 fallthrough)
401163 ret                                | -> ends B3
```

Leaders: `0x401146` (start), `0x401156` (after the `jne`), `0x40115d` (the `jne`
target), `0x401162` (the `jmp` target). Four basic blocks. Edges:

- B0 ends in `jne`: to B2 (taken, `0x40115d`) and to B1 (fallthrough, `0x401156`).
- B1 ends in `jmp`: to B3 (`0x401162`).
- B2 ends by fallthrough (its successor `0x401162` is a leader): to B3.
- B3 ends in `ret`: no successors.

A clean diamond, which is exactly the shape that teaches "the gate splits the
flow and both sides rejoin". Edge kinds worth labeling for the learner: taken,
fallthrough, unconditional.

## Function discovery in stripped binaries

`strip` removes `.symtab`, so `check` and `main` have no names and the symbol
table is empty. Disassembly must start from something other than a symbol.

For the curated `-O0` challenges, every C function opens with the frame-pointer
prologue `push rbp; mov rbp,rsp`, bytes `55 48 89 e5`. Scanning executable
sections for that pattern recovers function entry points. Verified in
`gate_stripped`: `0x401146` (was `check`) and `0x401164` (was `main`) both begin
`55 48 89 e5`; `_start` at `0x401060` does not (it has a different prologue), so
the scan cleanly separates user functions from the runtime start-up code.

Honest limits an adversarial check must record: this heuristic only finds
functions that keep a frame pointer. Anything built with `-O2`
(frame-pointer-omitted), or hand-written assembly, will be missed; real tools
add call-target recovery, symbol hints, and unwind-table (`.eh_frame`) parsing.
For rveng's curated, frame-pointer-preserving samples the prologue scan is
sufficient and honest, and it is the right first lesson in "how do you even find
a function when the names are gone". The stripped challenge disassembles a
discovered region by address, never by name, and grades a found-value answer, so
no symbol is ever leaked.

## Facts pulled forward for the KATs

- PLT entries: `0x401030 -> puts`, `0x401040 -> printf`, `0x401050 -> atoi`;
  GOT slots `0x404000/8/10`; `.rela.plt` symbol index is `r_info >> 32`.
- RIP-relative: `target = insn.address + insn.size + disp`; `0x401173 lea ->
  0x402004` (the flag string).
- `check` CFG: 4 basic blocks, leaders `0x401146/0x401156/0x40115d/0x401162`,
  diamond edges as above.
- Stripped discovery: prologue `55 48 89 e5` finds `check` and `main`, not
  `_start`; `.dynsym`/`.rela.plt`/`.plt` survive `strip` so imports stay named.
