<!-- ©AngelaMos | 2026 -->
<!-- 01-CONCEPTS.md -->

# Reverse-Engineering Concepts

Reverse engineering a binary is the practice of recovering what a program does
from the bytes that run, without the source code. You do it when there is no
source: analyzing malware, auditing a closed-source driver, understanding a
vulnerability from a shipped patch, checking whether a firmware image does what
its vendor claims. This document covers the concepts rveng teaches, grounded in
how real analysts work.

## Static versus dynamic analysis

There are two ways to study a binary.

- **Dynamic analysis** runs it and watches: a debugger, a sandbox, a tracer.
  You see real behavior, but you have to execute possibly-hostile code, and the
  code can detect the sandbox and lie.
- **Static analysis** reads the bytes without running them: parse the file
  format, disassemble the instructions, read the strings and symbols. Nothing
  executes, so nothing can attack you or hide from you by refusing to run.

rveng is entirely static, and that is not a limitation dodge. A large amount of
real reverse engineering is static. The clearest famous example: in 2017 the
WannaCry ransomware was slowed worldwide when an analyst found a hardcoded domain
name inside the sample that it checked before spreading, and registered that
domain. That domain was a "killswitch" that lived in the binary as a plain
string, the kind of artifact you recover by reading the file rather than
guessing. Reading strings and control flow out of a file is a first-class skill,
and it is the skill rveng grades.

## What a binary actually is

A compiled program on Linux is an ELF file (Executable and Linkable Format, the
System V ABI's format). It is not a blob. It has a rigid, documented structure:

```
+---------------------+  offset 0
| ELF header          |  magic, class, entry point, where the tables are
+---------------------+
| program headers     |  how the loader maps the file into memory (segments)
+---------------------+
| .text   (code)      |  the machine instructions
| .rodata (constants) |  string literals, read-only data
| .data   (globals)   |  writable initialized data
| ...                 |
+---------------------+
| section headers     |  a table describing every section above
+---------------------+
| .symtab / .strtab   |  function and variable names (removed when stripped)
+---------------------+
```

The ELF header at offset 0 is the map to everything else. Its first four bytes
are always `7f 45 4c 46` (`\x7fELF`). One field, `e_entry`, holds the virtual
address where execution begins. Another, `e_shoff`, points at the section header
table. Learning to read those fixed offsets by hand is `02-elf-anatomy`, and the
engine that does it is `elf.py`.

## Addresses, offsets, and why they differ

Two coordinate systems run through every binary, and confusing them is the most
common beginner mistake.

- A **file offset** is a position in the file on disk. Byte number 0x1154 in the
  file.
- A **virtual address** is where a byte lands in memory once the loader maps the
  file. Address 0x401154 at runtime.

They are related by the section that contains the byte: `vaddr = file_offset -
section.offset + section.addr`. The sample `gate` is compiled `-no-pie`, which
means it is not position-independent and its addresses are fixed at link time,
so the numbers in these docs are stable and you can reason about them directly.
Position-independent executables (the modern default) load at a random base, and
you would work in offsets from that base instead. rveng uses `-no-pie` on purpose
so the teaching addresses never move.

## Symbols, and the world without them

A **symbol** is a name attached to an address: the function `check` lives at
`0x401146`, the entry `main` at `0x401164`. Symbols live in `.symtab`, and names
in `.strtab`. They exist to help linkers and debuggers, not to run the program,
so a release build or a piece of malware usually **strips** them: the `.symtab`
section is deleted. The code still runs identically. It is just anonymous.

Stripping is why real reverse engineering is hard, and why rveng has a stripped
challenge. When `check` is no longer named, you cannot search for it. You have to
find functions another way (scan for the prologue that starts most functions),
read the disassembly directly, and recognize the `cmp` against a constant as the
gate. That is `discover.py` finding `sub_401146` where a symbol table would have
said `check`.

The one thing stripping does not remove is dynamic linking information. A program
that calls `printf` still needs the `.dynsym` and `.plt` machinery to find
`printf` in libc at load time. So even in a stripped binary, calls to library
functions can be recovered by name. That is what `plt.py` does.

## The PLT: how an external call gets a name back

When `gate` calls `atoi`, the compiler does not know where `atoi` will be in
memory, so it calls a small stub in the Procedure Linkage Table (`.plt`). That
stub jumps through a Global Offset Table (`.got.plt`) slot that the loader fills
in. The link between "this PLT stub" and "the name `atoi`" is stored in the
relocation table `.rela.plt`, which points into `.dynsym`, whose names live in
`.dynstr`.

```
call 0x401050          the code calls a PLT stub
  0x401050: jmp [rip+X]   the stub jumps through a GOT slot at address G
.rela.plt: G -> dynsym[i] the relocation says slot G binds symbol index i
.dynsym[i].name -> .dynstr the symbol's name is "atoi"
```

Walking that chain turns `call 0x401050` into `call atoi`. The engine does
exactly this in `plt.py`, and it is why the disassembly pane can label imported
calls instead of showing bare addresses.

## Reading a gate in assembly

The heart of most crackme-style challenges is a comparison feeding a conditional
jump. In `gate`, the `check` function contains:

```
cmp   DWORD PTR [rbp-0x4], 0x539     ; compare the input against 0x539 (1337)
jne   <fail path>                    ; if not equal, take the fail branch
<success path>
```

`0x539` is `1337` in decimal, and Intel-syntax capstone prints it as `0x539`.
Recognizing that the magic number is `1337`, read from the `cmp`, is
`05-disassembly`. Recognizing that flipping the `jne` (opcode byte `75`) so the
branch is never taken forces the success path is `03-patching`. The skill in both
cases is reading intent out of instructions.

## Patching: behavior is just bytes

A conditional jump `jne` is the two bytes `75 07` in this binary. Overwrite them
with `90 90` (two `nop` no-ops) and the jump is gone, so control falls straight
into the unlock path regardless of the input. That is binary patching: you change
behavior by editing bytes, no recompile. It is the mechanism behind historical
software cracks, behind legitimate hot-patching, and behind micro-patching a
vulnerable function without shipping a whole new build.

rveng grades a patch without running it. Each patch challenge ships the original
binary and a known-good patched target. Your submitted bytes are applied to the
original at the given offset, and the result is compared to the known-good target
with a byte diff. Equal means correct. This grades the exact skill (produce the
right edit) with zero execution. That is the trick in `patch.py`.

## The solve-then-reveal loop

The pedagogy rveng preserves from its predecessor is simple and strict:

1. A challenge gives you a binary and a concrete mission.
2. You use the tools to reach an answer from the binary alone.
3. You submit. The engine grades it.
4. Only a correct answer reveals the original C source.

Revealing source only after a correct answer is what makes the loop teach. You
must reach the answer from the machine evidence, then you get to see you were
right and why. This is only possible because every answer is machine-checkable,
which forces every challenge into one of three grading categories:

- **found-value**: locate a number or string in the binary and submit it. The
  magic `1337`, or the string `the_flag_is_here`. Numbers are normalized so
  `0x539`, `539h`, and `1337` all match.
- **identified-symbol**: name a function, section, or symbol. Answer `check`,
  matched case-insensitively.
- **patched-bytes**: edit bytes to change behavior, graded by static diff against
  a known-good target.

Every one of the six challenges is one of these three, and that mapping is the
bridge between "reverse engineering as a craft" and "reverse engineering a
machine can grade." The next document shows how the system is built around it.
