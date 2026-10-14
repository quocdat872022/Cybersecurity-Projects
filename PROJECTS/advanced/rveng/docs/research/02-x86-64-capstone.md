<!-- ©AngelaMos | 2026 -->
<!-- 02-x86-64-capstone.md -->

# x86-64 Disassembly and Capstone Research

Primary sources: the Intel 64 and IA-32 Architectures Software Developer
Manuals for instruction semantics, and the Capstone engine documentation for
API usage. Cross-checked against `objdump -d -M intel` on the local sample.

## Minimum x86-64 mental model for these challenges

A learner solving the five modules needs to recognize a small instruction set,
not the whole ISA. The instructions that actually appear in the challenge
binaries:

- `mov dst, src` : copy a value. `mov dword ptr [rbp-4], edi` stores the first
  argument (edi) into a local stack slot.
- `cmp a, b` : compute `a - b` and set flags, discarding the result. This is
  how a program tests a value. The compared constant is the thing a learner
  hunts for.
- `test a, b` : bitwise AND setting flags, commonly `test eax, eax` to check
  for zero.
- the jcc family (`je`, `jne`, `jg`, `jle`, ...) : conditional jump based on the
  flags a preceding `cmp`/`test` set. `jne` after `cmp x, 0x539` means "branch
  if x is not 1337".
- `jmp` : unconditional jump.
- `call` / `ret` : function call and return.
- `lea` : load effective address, often used to point at a string in `.rodata`.
- `push` / `pop` : stack, seen in function prologue/epilogue with `rbp`.

Registers that show up: `rax`/`eax` (return value and scratch), `rbp`/`rsp`
(frame and stack pointers), `edi`/`esi`/`edx` (first three integer arguments in
the System V AMD64 calling convention).

Intel syntax is used throughout (`mov dst, src`, destination first) rather than
AT&T (`mov src, dst`, `%` and `$` sigils) because it is easier for a beginner
and matches `objdump -d -M intel`.

## The gate pattern

The whole disassembly module rests on one recognizable shape: a `cmp` against a
constant followed by a conditional jump. In the sample, `check(int n)` compiles
to exactly this. From `objdump -d -M intel gate`:

```
401146 <check>:
  40114d: 81 7d fc 39 05 00 00   cmp    DWORD PTR [rbp-0x4],0x539
  401154: 75 07                  jne    40115d <check+0x17>
  401156: b8 01 00 00 00         mov    eax,0x1
  40115b: eb 05                  jmp    401162 <check+0x1c>
  40115d: b8 00 00 00 00         mov    eax,0x0
```

`0x539` = 1337. The C source compared `n == 1337`. A learner reads the `cmp`,
converts the hex, and has the magic number. The engine's job is to surface this
`cmp` clearly and annotate that the following `jne` is the gate.

## Capstone API

Installed reference: capstone 5.0.9 (Python binding).

Construction and iteration:

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.syntax = CS_OPT_SYNTAX_INTEL   # = 1; Intel is also the x86 default
for ins in md.disasm(code_bytes, start_vaddr):
    ins.address    # int, virtual address of the instruction
    ins.mnemonic   # str, e.g. "cmp"
    ins.op_str     # str, e.g. "dword ptr [rbp - 4], 0x539"
    ins.bytes      # bytes, the raw machine bytes of this instruction
    ins.size       # int, length in bytes
```

`md.disasm(code, addr)` yields instructions until it hits bytes it cannot
decode. For the engine, `code` is the `.text` bytes and `addr` is `.text`'s
virtual address, so `ins.address` lines up with `readelf`/`objdump` addresses.

## objdump vs capstone agreement (the M1 KAT)

Disassembling the exact bytes of `check()` at vaddr 0x401146 with capstone
(Intel syntax) produced, instruction for instruction:

```
0x401146: push   rbp                          [55]
0x401147: mov    rbp, rsp                      [4889e5]
0x40114a: mov    dword ptr [rbp - 4], edi      [897dfc]
0x40114d: cmp    dword ptr [rbp - 4], 0x539    [817dfc39050000]
0x401154: jne    0x40115d                      [7507]
0x401156: mov    eax, 1                         [b801000000]
0x40115b: jmp    0x401162                       [eb05]
0x40115d: mov    eax, 0                         [b800000000]
0x401162: pop    rbp                            [5d]
0x401163: ret                                   [c3]
```

Every address, mnemonic, operand, and byte string matches `objdump -d -M intel`.
The only differences are cosmetic formatting (capstone renders `0x539` where
older objdump may print the same value, and omits the `<check+0x17>` symbol
annotation that objdump adds from the symbol table). This byte-and-mnemonic
agreement is the known-answer test the M1 `disasm` module is verified against:
disassembling this fixed byte range must reproduce this instruction sequence.

## Annotation the engine adds

Capstone gives raw instructions. The engine adds a thin annotation layer for
teaching:
- mark `cmp`/`test` as comparisons and surface the immediate operand in both
  hex and decimal (so `0x539` is shown as 1337 without the learner converting).
- mark jcc instructions as the conditional branch that acts on the preceding
  comparison.
- resolve intra-function jump/call targets to a relative label
  (`check+0x17`) using the function's start address, matching objdump's
  readability, sourced from the symbol table when present.

## Facts an adversarial check confirmed or corrected

- Confirmed: capstone 5.0.9 with `md.syntax = 4` reproduces objdump Intel-syntax
  disassembly byte-for-byte on the sample; the agreement is real, not assumed.
- Confirmed: `0x539` decodes to 1337 and originates from the source `n == 1337`.
- Corrected: `CS_OPT_SYNTAX_INTEL` is 1, not 4. The value 4 is
  `CS_OPT_SYNTAX_MASM`, which happens to render these simple instructions
  identically to Intel, so an early proof script using the literal 4 produced
  correct-looking output by coincidence. Intel is already the x86 default in
  capstone 5.0.9 (verified: default and explicit-Intel yield identical output,
  AT&T differs). The engine sets `CS_OPT_SYNTAX_INTEL` by name, never a literal.
