<!-- ©AngelaMos | 2026 -->
<!-- 01-elf-format.md -->

# ELF Format Research

Primary source: the System V Application Binary Interface and the ELF-64
Object File Format specification. Every field size and offset below is
cross-checked against a real binary compiled locally.

## Ground-truth sample

```
gate.c compiled with: gcc -no-pie -fno-stack-protector -O0 -o gate gate.c
file: ELF 64-bit LSB executable, x86-64, EXEC, dynamically linked, not stripped
```

Chosen `-no-pie` so the load addresses are fixed and readable (EXEC type, not a
PIE/DYN shared object with load-time relocation). This is the shape the curated
challenge binaries use so a learner sees stable addresses.

## ELF header (Elf64_Ehdr)

`readelf -h gate` reported, and the first 64 raw bytes confirm, this layout.
Offsets are into the file from byte 0.

| Off | Size | Field | Value in sample | Raw bytes |
|-----|------|-------|-----------------|-----------|
| 0x00 | 16 | e_ident | magic + class + data + version | `7f 45 4c 46 02 01 01 00` then padding |
| 0x10 | 2 | e_type | EXEC (2) | `02 00` |
| 0x12 | 2 | e_machine | x86-64 (62) | `3e 00` |
| 0x14 | 4 | e_version | 1 | `01 00 00 00` |
| 0x18 | 8 | e_entry | 0x401060 | `60 10 40 00 00 00 00 00` |
| 0x20 | 8 | e_phoff | 64 | `40 00 00 00 00 00 00 00` |
| 0x28 | 8 | e_shoff | 13984 (0x36a0) | `a0 36 00 00 00 00 00 00` |
| 0x30 | 4 | e_flags | 0 | `00 00 00 00` |
| 0x34 | 2 | e_ehsize | 64 | `40 00` |
| 0x36 | 2 | e_phentsize | 56 | `38 00` |
| 0x38 | 2 | e_phnum | 14 | `0e 00` |
| 0x3a | 2 | e_shentsize | 64 | `40 00` |
| 0x3c | 2 | e_shnum | 30 | `1e 00` |
| 0x3e | 2 | e_shstrndx | 29 | `1d 00` |

e_ident breakdown (the first 16 bytes):
- bytes 0-3: magic `7f 45 4c 46` = `\x7f E L F`. Every ELF starts with these.
- byte 4 (EI_CLASS): `02` = ELFCLASS64 (64-bit). `01` would be 32-bit.
- byte 5 (EI_DATA): `01` = little-endian (ELFDATA2LSB).
- byte 6 (EI_VERSION): `01`.
- bytes 7-15: OS/ABI + padding, zero here.

The raw hex cross-check is exact: the entry point bytes at file offset 0x18 are
`60 10 40 00` little-endian = 0x401060, matching both `readelf -h` and the entry
point of `.text`. The section header table offset at 0x28 is `a0 36 00 00` =
0x36a0 = 13984, matching e_shoff.

## Section header table (Elf64_Shdr)

Located at e_shoff (0x36a0), e_shnum (30) entries of e_shentsize (64) bytes
each. Section names are indices into the section named by e_shstrndx (29,
`.shstrtab`). Sections relevant to the learning modules, from `readelf -S`:

| Nr | Name | Type | Address | Offset | Size | Flags |
|----|------|------|---------|--------|------|-------|
| 11 | .init | PROGBITS | 0x401000 | 0x1000 | 0x17 | AX |
| 12 | .plt | PROGBITS | 0x401020 | 0x1020 | 0x40 | AX |
| 13 | .text | PROGBITS | 0x401060 | 0x1060 | 0x182 | AX |
| 15 | .rodata | PROGBITS | 0x402000 | 0x2000 | 0x30 | A |
| 24 | .data | PROGBITS | 0x404018 | 0x3018 | 0x10 | WA |
| 25 | .bss | NOBITS | 0x404028 | 0x3028 | 0x8 | WA |
| 27 | .symtab | SYMTAB | 0 | 0x3048 | 0x378 | |
| 28 | .strtab | STRTAB | 0 | 0x33c0 | 0x1ca | |

Key facts the engine must model:
- Flags: A = allocated into memory, X = executable, W = writable. `.text` is
  AX (code), `.rodata` is A (read-only data), `.data` is WA, `.bss` is WA.
- `.bss` type is NOBITS: it occupies memory at runtime but has zero size in the
  file (Size 0x8 but no file bytes). The engine must not read file bytes for a
  NOBITS section.
- A section with Address 0 is not loaded into the process image (`.symtab`,
  `.strtab`, `.shstrtab`). These exist only in the file.
- The entry point 0x401060 equals `.text` Address, and the symbol table shows
  `_start` at 0x401060. Entry is the first instruction the loader jumps to.

## Program header table (Elf64_Phdr)

Located at e_phoff (64), e_phnum (14) entries of e_phentsize (56) bytes. These
describe segments: how the file maps into memory at load time. From
`readelf -l`, the LOAD segments and their flags:

| Offset | VirtAddr | FileSiz | Flags | Holds |
|--------|----------|---------|-------|-------|
| 0x0000 | 0x400000 | 0x568 | R | ELF header + read-only metadata |
| 0x1000 | 0x401000 | 0x1ed | R E | .init .plt .text .fini (code) |
| 0x2000 | 0x402000 | 0x14c | R | .rodata + eh_frame |
| 0x2df8 | 0x403df8 | 0x230 | RW | .data .bss and relro |

Sections are the linker/analysis view. Segments are the loader view. The engine
parses sections for the learning modules (naming, layout) and can show segments
for the elf-anatomy module to explain how file bytes become a running process.

## Symbol table (Elf64_Sym)

`.symtab` at file offset 0x3048, entry size 24 (0x18). Names index into
`.strtab`. Sample function symbols from `readelf -s`:

| Value | Size | Type | Bind | Name |
|-------|------|------|------|------|
| 0x401060 | 34 | FUNC | GLOBAL | _start |
| 0x401146 | 30 | FUNC | GLOBAL | check |
| 0x401164 | 126 | FUNC | GLOBAL | main |

Each symbol carries value (address), size, a type (FUNC/OBJECT/etc.), a binding
(LOCAL/GLOBAL/WEAK), and a section index. `check` at 0x401146 with size 30 is
the target of the strings-symbols and disassembly modules. A stripped binary
has no `.symtab`, which is why later challenges can strip symbols to force
learners into raw disassembly.

## What we hand-roll vs delegate

Hand-roll (this is the ELF-format learning surface):
- e_ident + Elf64_Ehdr field parse from raw bytes (the table above).
- Section header table walk: read e_shoff/e_shnum/e_shentsize, iterate entries,
  resolve names via e_shstrndx.

Delegate to pyelftools where hand-rolling adds no pedagogical value:
- Program header details, relocation tables, dynamic section, DWARF.

pyelftools 0.33 is the installed reference and is used to cross-check the
hand-rolled parser in the M1 known-answer tests: the hand-rolled header and
section fields must equal what pyelftools reports for the same binary.

## Facts an adversarial check confirmed or corrected

- Confirmed: entry point, e_shoff, e_shnum, and all e_ident bytes match the raw
  file bytes exactly (not taken from memory or a generic ELF diagram).
- Confirmed: `.bss` is NOBITS with a nonzero memory size and no file content;
  the parser must special-case it.
- Corrected assumption: an EXEC (non-PIE) binary has fixed addresses; a default
  `gcc` build is PIE (ET_DYN) with load-relative addresses. The challenge
  binaries are compiled `-no-pie` on purpose so addresses in `readelf`,
  `objdump`, and the engine all agree with what a learner sees.
