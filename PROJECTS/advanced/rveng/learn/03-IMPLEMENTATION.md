<!-- ©AngelaMos | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# Implementation

A walk through the engine, module by module, against the sample `gate` binary.
Every address and offset below is real and reproducible: `gate` is compiled with
`gcc -no-pie -fno-stack-protector -O0`, so nothing moves. Code is referenced by
function name, never line number, because line numbers rot.

## elf.py: reading the file format from raw bytes

`elf.py` hand-rolls the ELF64 parser with `struct`. It does not use a library to
read the format, on purpose: the point is to learn where every field lives. The
tests then cross-check the hand-rolled result against pyelftools
(`test_matches_pyelftools`), so pyelftools is a correctness oracle in the test
suite, not a dependency the engine leans on at runtime.

`parse_header` is the entry point. It rejects anything that is not ELF64:

- The first four bytes must be `\x7fELF` (`ELF_MAGIC`).
- Byte 4 (`EI_CLASS`) must be `ELFCLASS64`.
- Byte 5 (`EI_DATA`) selects endianness, turned into a `struct` prefix (`<` for
  little-endian, which is what x86-64 uses).

Then it reads fixed offsets straight out of the header: `e_entry` at `0x18`,
`e_shoff` at `0x28`, `e_shnum` at `0x3C`, and so on. For `gate` this yields
`e_entry = 0x401060`, `e_shoff = 0x36a0` (13984), `e_shnum = 30`. `_validate_
section_table` then bounds-checks the section table so a malformed file raises
`NotAnElf` instead of reading out of range.

`parse_sections` reads all `e_shnum` section headers, then resolves each
section's name. Names are not stored inline; each header holds a `name` offset
into a dedicated string section, and the header's index is `e_shstrndx`. The
parser reads that section's bytes once and pulls each name as a C string. That is
how a nameless index becomes `.text`, `.rodata`, `.symtab`.

`parse_symbols` finds the `.symtab` section, follows its `link` field to the
matching string table, and reads each 24-byte symbol entry: name offset, value
(the symbol's address), size, and a packed `info` byte whose low nibble is the
type and high nibble is the binding. For `gate`, this recovers `check` at
`0x401146` with size 30, and `main` at `0x401164`. `ElfImage` wraps all of this
and offers `section(name)`, `symbol(name)`, and `functions()` (symbols whose type
is `STT_FUNC`).

The one design note worth internalizing: a section can be `SHT_NOBITS` (`.bss`),
meaning it occupies memory but no file bytes. `Section.file_bytes` returns empty
for those, so nothing tries to read file content that is not there.

## hex.py: the canonical dump

`hex.py` renders the same layout as `xxd`: an 8-hex-digit offset, sixteen bytes
of hex split into two groups of eight, then the ASCII gutter. `HexLine.ascii_
gutter` prints a byte as its character only when it is in the printable range
`0x20` to `0x7E`, and a `.` otherwise. That gutter is the whole skill of
`01-hex-reading`: the secret string `the_flag_is_here` is invisible in the hex
columns but obvious in the gutter, sitting in `.rodata` at file offset `0x2004`.

## strings.py: printable runs

`extract` walks the bytes, accumulating a run whenever it sees a printable byte
and flushing the run as a `FoundString` when it breaks, if the run met the
minimum length. `extract_in_section` scopes that to one section's bytes while
keeping file-relative offsets, so you can ask specifically for the strings in
`.rodata`. This is the cheap win of reverse engineering: before disassembling
anything, read the strings, and a password or a format string often falls out.

## patch.py: editing behavior without running it

Three functions, all pure:

- `apply(original, offset, new_bytes)` returns a new buffer with the edit
  written in, bounds-checked, and length-preserving. A patch never changes the
  file size.
- `diff(a, b)` returns the per-byte differences between two equal-length
  buffers.
- `verify_patch(original, offset, submitted, known_good)` applies the submission
  and returns whether the result equals the known-good target.

This is the mechanism that grades a patch challenge with no execution. For the
gate, the `jne` at file offset `0x1154` is the bytes `75 07`. Overwriting them
with `90 90` produces exactly the known-good patched target, so `verify_patch`
returns true. Nothing is run; two buffers are compared.

## disasm.py: decoding x86-64 with capstone

`_new_engine` configures capstone for 64-bit x86 in Intel syntax with detail on.
Intel syntax is the one where the constant prints as `0x539`; the setting is
`CS_OPT_SYNTAX_INTEL`. Detail mode is required because the engine inspects each
instruction's operands, not just its text.

Every decoded instruction becomes an `Instruction` dataclass carrying its
address, mnemonic, operand string, raw bytes, and three annotations that the
higher layers depend on:

- `immediate`: the immediate operand of a non-flow instruction, so `cmp [rbp-4],
  0x539` exposes `0x539`. This is pulled by `_immediate`, which reads the
  `X86_OP_IMM` operand.
- `branch_target`: for a control-flow instruction (a conditional jump, `call`,
  or `jmp`), the immediate is the destination address instead of a data value.
  The engine routes the immediate to `branch_target` for flow ops and to
  `immediate` for everything else, so the two never get confused.
- `rip_target`: for a RIP-relative memory operand, the absolute address it
  points at, computed by `_rip_target` as `instruction address + instruction
  size + displacement`. This is how `lea rax, [rip+X]` loading the secret string
  resolves to `0x402004`.

There are three ways to disassemble:

- `disassemble_symbol` uses a symbol's section index, value, and size to carve
  exactly that function's bytes. This is the clean path when symbols exist.
- `disassemble_at` disassembles from a raw virtual address until the first `ret`.
  This is the path for a stripped binary, where you have an address (from
  discovery) but no size.
- `disassemble_text` decodes the whole `.text` section for whole-binary analysis
  like cross-referencing.

`find_gate` returns the first comparison instruction that carries an immediate,
which for `gate` is the `cmp ..., 0x539`. That is the machine reading the gate
the same way a learner does.

## plt.py: giving imported calls their names back

A stripped or dynamically linked binary calls libc functions through PLT stubs.
`plt.py` reconstructs the stub-to-name mapping the way the loader would:

- `_dynamic_names` reads `.dynsym` and resolves each dynamic symbol's name from
  `.dynstr`.
- `_got_to_name` reads `.rela.plt`. Each relocation has a target GOT address
  (`r_offset`) and a packed `r_info` whose top 32 bits are the dynamic-symbol
  index. It maps each GOT slot to the imported name.
- `_stub_got_slot` finds the `jmp [rip+disp]` inside a 16-byte PLT entry (the
  opcode is `ff 25`) and computes which GOT slot it jumps through, as `entry
  address + jump offset + 6 + displacement`.
- `plt_map` ties it together: for every PLT stub, find its GOT slot, look up the
  name bound to that slot.

For `gate` this produces exactly `0x401030 -> puts`, `0x401040 -> printf`,
`0x401050 -> atoi`. That is why the disassembly of `main` can show `call atoi`
instead of `call 0x401050`.

## xref.py and cfg.py: structure over the instruction stream

`xref.py` turns decoded instructions into references. Every `branch_target`
becomes a call or branch reference, every `rip_target` becomes a data reference.
`build_xrefs` groups them by the address they point at, so you can ask "who
references `check`?" and `xrefs_to` filters to one target. Running it over the
sample finds `main` calling `check`.

`cfg.py` builds a control-flow graph for a single function using the classic
leader algorithm:

1. `_leaders` marks basic-block boundaries. A block starts at the first
   instruction, at any instruction immediately after a terminator (a conditional
   branch, `jmp`, or `ret`), and at any branch target that lands inside the
   function.
2. `build_cfg` slices the instruction stream at those leaders into `BasicBlock`s.
3. It connects them: a conditional branch emits a `taken` edge to its target and
   a `fallthrough` edge to the next block; a `jmp` emits a `jump` edge; a plain
   block falls through; a `ret` emits nothing.

For `check`, this produces the diamond you would expect: an entry block with the
`cmp`/`jne`, a taken edge to the fail path and a fallthrough edge to the success
path.

## discover.py: finding functions with no symbols

When a binary is stripped, `functions()` returns nothing, so navigation needs
another anchor. `discover_functions` scans every executable section for the
standard function prologue `55 48 89 e5`, which is `push rbp; mov rbp, rsp`, the
frame setup that begins most `-O0` functions. Each hit becomes a `Discovered
Function` labeled `sub_<address>`. On `gate_stripped` this rediscovers the entry
of `check` at `0x401146` even though its name is gone, and the disassembly-by-
address path takes over from there. This is exactly how you work a real stripped
binary: no names, so you find code by its shape.

## challenge.py: the grader and the reveal

`challenge.py` holds the three answer specs (`FoundValue`, `IdentifiedSymbol`,
`PatchedBytes`) and the `grade` function that dispatches on which one a challenge
uses:

- A `FoundValue` numeric answer is graded through `normalize_int`, which accepts
  `0x539`, `539h`, and `1337` and compares as integers. A string `FoundValue` is
  compared after trimming and lowercasing.
- An `IdentifiedSymbol` is compared case-insensitively against the known name.
- A `PatchedBytes` submission is graded by `verify_patch` against the known-good
  target.

The load-bearing behavior is at the end of `grade`: it returns the challenge's
source only when the answer is correct. A wrong answer returns `revealed_source =
None`. That single conditional is the solve-then-reveal pedagogy, and it works
because every answer is checkable before the reveal. The API layer never has to
know how grading works; it calls `grade`, and hands back whatever source (if any)
comes out.
