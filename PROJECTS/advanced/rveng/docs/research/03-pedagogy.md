<!-- ©AngelaMos | 2026 -->
<!-- 03-pedagogy.md -->

# Reverse-Engineering Pedagogy Research

Source: the design of the predecessor rveng plus how the five modules actually
teach. The goal is a machine-checkable version of the same solve-then-reveal
loop, so the platform can grade a learner instead of just handing them tools.

## The solve-then-reveal loop

The predecessor's model, kept intact:
1. A module teaches one skill through a short concept note.
2. A challenge gives a compiled binary and a mission ("find the magic number").
3. The learner uses the tools (now in-browser) to solve it.
4. After solving, the original C source is revealed so the learner connects the
   machine-level evidence back to the code that produced it.

Revealing source only after a correct answer is what makes the loop teach. The
learner must reach the answer from the binary, then gets to see they were right
and why. This requires the answer to be checkable before the reveal, which the
predecessor could not do (it just trusted the learner). The platform grades.

## Answer-spec categories (what the verifier must grade)

Every challenge needs a machine-checkable answer. Three categories cover all
five modules, each grounded in the sample `gate` binary:

- **found-value** : the learner locates a value in the binary and submits it.
  Example: the magic number in `check()` is `0x539` = 1337, read from
  `cmp DWORD PTR [rbp-0x4],0x539`. The verifier accepts the value in decimal or
  hex, normalized before comparison. Also covers finding a string
  (`the_flag_is_here` at .rodata 0x402004) or an offset.

- **identified-symbol** : the learner names a function, section, or symbol.
  Example: "which function decides the outcome?" answer `check` (at 0x401146,
  size 30 in `.symtab`). The verifier compares against the known symbol name,
  case-insensitive.

- **patched-bytes** : the learner changes bytes to alter behavior and submits
  the patched byte range. Example: flip the gate by changing the `jne` (opcode
  `75`) at 0x401154 so the unlock path is always taken. The verifier diffs the
  submission against a known-good patched target statically. It never runs the
  result.

## Module to category mapping

| # | Module | Skill | Answer category |
|---|--------|-------|-----------------|
| 01 | hex-reading | read hex dumps, locate values | found-value |
| 02 | elf-anatomy | header, sections, entry point | found-value / identified-symbol |
| 03 | patching | change bytes, change behavior | patched-bytes |
| 04 | strings-symbols | find names and strings | found-value / identified-symbol |
| 05 | disassembly | read assembly, find the gate | found-value |

## What makes a good challenge per module

- hex-reading: a value or ASCII string is visible in the hex dump at a
  findable offset. The learner practices reading offsets and the ASCII gutter.
- elf-anatomy: the answer is a header field or a section fact (entry point,
  which section holds a string, how many sections). Teaches the file's skeleton.
- patching: a single conditional jump or comparison gates behavior; a
  one-to-few-byte edit changes the outcome. Teaches that behavior is bytes.
- strings-symbols: a password or a function name is recoverable from `.rodata`
  or `.symtab` without disassembly. Teaches the cheap wins before the hard work.
- disassembly: symbols may be stripped so the learner must read the `cmp`/jcc
  gate directly. Teaches assembly as ground truth when names are gone.

## Grading rules

- found-value: normalize both sides to an integer when numeric (accept `0x539`,
  `539h`, `1337`), or exact-match after trim/lowercase when a string.
- identified-symbol: exact match after trim/lowercase against the known name.
- patched-bytes: the submitted bytes, applied at the specified offset to the
  original, must equal the known-good patched target under a static byte diff.
  No execution, ever.

## Facts an adversarial check confirmed

- Confirmed against the real binary: the magic number is `0x539` (1337), the
  deciding function is `check` at 0x401146, and the gate is the `jne` at
  0x401154. These are the concrete answers the sample's challenges grade.
- The reveal-after-solve ordering is the load-bearing pedagogy: source is
  withheld until a correct submission, which is only possible because every
  answer is machine-checkable.
