<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# Challenges

Six challenges over one binary. They span the five core reverse-engineering
skills, and the sixth removes the training wheels by stripping the symbols. Each
is graded, and each reveals its source only when you are right. The answers are
printed here because this is the teaching document; solve them from the binary
first, then check yourself.

The sample `gate` reads a number from `argv`, compares it against `1337` in a
function called `check`, and prints the secret `the_flag_is_here` when the number
matches. All six challenges are that one program, seen from different angles.

## The five skills, mapped to grading

Every challenge is one of three machine-checkable answer categories. That mapping
is what lets a machine grade a craft:

| # | Challenge | Module | Skill | Category |
|---|-----------|--------|-------|----------|
| 01 | Read the hex | hex-reading | read a dump, find a value | found-value |
| 02 | Find the entry point | elf-anatomy | read the ELF header | found-value |
| 03 | Flip the gate | patching | change bytes, change behavior | patched-bytes |
| 04 | Name the function | strings-symbols | read the symbol table | identified-symbol |
| 05 | Find the gate | disassembly | read the assembly | found-value |
| 06 | Gate in the dark | disassembly (stripped) | work without symbols | found-value |

## 01: Read the hex

Mission: a secret string sits in the binary's read-only data. Open the hex
viewer and read the ASCII column to recover it.

Answer: `the_flag_is_here`, at file offset `0x2004` in `.rodata`.

What it teaches: the two halves of a hex dump. The hex columns are noise to a
human; the ASCII gutter on the right is where a string becomes legible. This is
the first move on any unknown file, and it is free.

## 02: Find the entry point

Mission: every ELF file records where execution begins. Read the header and find
the entry point, the `e_entry` field.

Answer: `0x401060` (decimal `4198496`). Both forms are accepted.

What it teaches: the ELF header is the map to the whole file, and `e_entry` is a
fixed field at offset `0x18`. Learning that the header is a rigid table you can
read by hand, rather than magic, is the foundation for everything else.

## 03: Flip the gate

Mission: the check at file offset `0x1154` is a conditional jump (`jne`, bytes
`75 07`) that skips the unlock path. Patch those two bytes so the branch is never
taken and the unlock path always runs. Submit the two replacement bytes as hex.

Answer: `9090` (two `nop`s), applied at offset `0x1154`.

What it teaches: behavior is bytes. A single conditional jump gates the outcome,
and neutralizing it with two `nop`s forces the success path. The grader applies
your bytes to the original and compares against a known-good patched target with
a static diff, so you are graded on producing the exact edit, and nothing is ever
run.

## 04: Name the function

Mission: one function decides whether the gate opens. Read the symbol table and
name it.

Answer: `check` (at `0x401146`, size 30, in `.symtab`). Matched
case-insensitively.

What it teaches: symbols are names attached to addresses, and when they are
present they hand you the map for free. This is the cheap path that the stripped
challenge later takes away.

## 05: Find the gate

Mission: this binary checks a number against a magic value. Disassemble the check
function and find the constant it compares against.

Answer: `1337` (the `cmp ..., 0x539`). Accepted as `1337`, `0x539`, or `539h`.

What it teaches: reading intent out of instructions. The magic number is not a
string and not a symbol; it is an immediate operand inside a `cmp`, and the only
way to it is to read the disassembly of `check`.

## 06: Gate in the dark

Mission: this binary is stripped, so there are no function names to look up.
Discover the functions by their prologue, disassemble the one that checks a
number, and read the constant it compares against.

Answer: `1337`, same as challenge 05, but reached with no symbol table.

What it teaches: the real-world case. Malware and release builds are stripped, so
`04`'s symbol lookup and `05`'s named disassembly both fail here. You find code
by its shape (the `push rbp; mov rbp, rsp` prologue), disassemble by raw address
until the `ret`, and recognize the same gate. This is reverse engineering when
the binary is not trying to help you.

## Extending the platform

Adding a challenge is adding an asset directory, no code change. Each challenge
is a folder under `challenges/` with three files:

```
challenges/07-your-challenge/
  challenge.json   id, module, title, mission, and the answer spec
  target           the compiled binary to analyze
  source.c         the source revealed on a correct answer
```

The `answer` object in `challenge.json` picks one of the three grading
categories:

```
{ "category": "found_value",      "expected": 1337 }
{ "category": "found_value",      "expected": "the_flag_is_here" }
{ "category": "identified_symbol","name": "check" }
{ "category": "patched_bytes",    "offset": 4436, "patch": "9090" }
```

The loader validates the directory at startup, and one malformed challenge is
skipped with a warning rather than crashing the whole set. From there, ideas that
fit the existing engine without any new capability:

- A challenge that asks which section holds a given string, graded as an
  identified-symbol on the section name.
- A multi-byte patch that changes a comparison constant rather than removing a
  jump.
- A binary with a decoy function so function discovery returns more than one
  candidate and the learner has to pick the real gate from the disassembly.
- A found-value challenge on a RIP-relative data reference, so the learner has to
  compute an absolute address from an instruction the way `disasm.py` does.

Ideas that need new engine work, and would be real projects: a second
architecture (ARM64 via capstone's other modes), a dynamic-analysis face behind a
separate sandboxed design that preserves the no-execution posture of this
backend, or an auto-laid-out graph view over the existing control-flow graph.
