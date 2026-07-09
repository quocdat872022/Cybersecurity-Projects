<!-- ©AngelaMos | 2026 -->
<!-- INDEX.md -->

# rveng Domain Research Archive

Reverse-engineering-platform research: the ELF file format, x86-64 disassembly
via capstone, the solve-then-reveal teaching model, and the no-execution
security posture. Every field size, offset, opcode, and disassembly line is
cross-checked against a real binary compiled locally (`gate`, built with
`gcc -no-pie -fno-stack-protector -O0`), not taken from memory or a generic
diagram. Each doc carries the VERIFIED fact where an adversarial check overruled
the first pass.

Honest grounding to keep across all of these: the engine reads bytes, it never
executes them. Challenge binaries are curated and pre-compiled; all analysis is
read-only static parsing and disassembly; patch challenges are graded by static
byte diff against a known-good target. This is what makes a web app that eats
binaries safe, and it is a hard constraint, not a preference.

| File | Read when |
|---|---|
| `01-elf-format.md` | implementing `engine/elf.py`: the Elf64 header field table with raw-byte cross-check, section/segment/symbol tables, NOBITS handling, what we hand-roll vs delegate to pyelftools, why the challenges are `-no-pie` |
| `02-x86-64-capstone.md` | implementing `engine/disasm.py`: the minimal x86-64 instruction set these challenges use, the cmp/jcc gate pattern, capstone 5.0.9 API, the objdump-vs-capstone byte-for-byte agreement KAT, the Intel-syntax constant correction |
| `03-pedagogy.md` | implementing `engine/challenge.py` and the runner: the solve-then-reveal loop, the three answer-spec categories (found-value, identified-symbol, patched-bytes), module-to-category mapping, grading rules |
| `04-no-execution-posture.md` | any API or engine work touching binaries: the enumeration proving every operation is read-only, why patch grading is a static diff, the API input constraints, the standing no-execution rule |
| `05-static-analysis.md` | implementing the M3.5 depth engine (`plt.py`, `xref.py`, `cfg.py`, stripped discovery): PLT/GOT/.rela.plt/.dynsym import resolution, RIP-relative operand math, the basic-block leader algorithm, prologue-scan function discovery, all KAT-traced to `gate` and `gate_stripped` |

Key verified facts pulled forward:
- ELF header cross-checks exactly to raw bytes: entry `0x401060`, e_shoff
  `0x36a0` (13984), e_shnum 30, e_ident `7f 45 4c 46 02 01 01`.
- The sample gate: `check` at `0x401146` (size 30), magic `cmp ...,0x539` = 1337
  at `0x40114d`, gate `jne` at `0x401154`, secret `the_flag_is_here` at .rodata
  `0x402004`.
- capstone 5.0.9 reproduces objdump Intel disassembly byte-for-byte;
  `CS_OPT_SYNTAX_INTEL` is 1 (not 4, which is MASM), and Intel is already the
  x86 default.

Build contract and full architecture: `../plans/rveng-design.md`.
Implementation plan: `../plans/rveng-implementation-plan.md`.
