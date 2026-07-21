<!-- ©AngelaMos | 2026 -->
<!-- 00-OVERVIEW.md -->

# rveng: Overview

rveng is an interactive reverse-engineering learning platform. It hands you a
real compiled binary, asks a concrete question about it ("what number does the
check compare against?"), gives you an in-browser hex viewer, disassembler,
section map, and string scanner to answer it, and grades your answer. Only when
you are right does it reveal the original C source, so you connect the machine
code you just read back to the code that produced it.

It is one framework-free Python analysis engine wearing three faces: a web app,
an HTTP API, and (by construction) an embeddable library. The engine parses
ELF, disassembles x86-64 with capstone, resolves imports through the PLT, builds
control-flow graphs, finds functions in stripped binaries, and verifies
challenge answers. The FastAPI layer is a thin read-only adapter over it. The
React app is the face a learner touches.

This folder teaches how the whole thing works, from the security posture that
makes it safe down to the byte offsets in the sample binary.

## The one rule that shapes everything: no execution

rveng never runs a binary. Every operation is reading and parsing bytes:

- Hex dump, ELF header parse, section walk, symbol read, string scan: all pure
  byte reads.
- Disassembly is decoding, not running. capstone reads instruction bytes and
  returns their text form. It never transfers control to the decoded code.
- Patch challenges are graded by a static byte diff against a known-good patched
  target. The patched binary is never executed.

A naive "web app that analyzes binaries" invites users to upload executables the
server then runs, which means sandboxing untrusted native code forever. rveng
sidesteps that entire attack surface. Challenge binaries are curated and
pre-compiled by the author and shipped as static assets. If nothing is ever
executed, there is no arbitrary-code-execution surface, no sandbox to escape, and
no resource-exhaustion path through a hostile binary. This constraint is
load-bearing, not a preference. Adding a feature that runs a binary would require
a separate design that keeps this posture.

## Capabilities

- A hand-rolled ELF64 parser: header, section table, symbol table, all read
  straight from raw bytes and cross-checked in the tests against pyelftools.
- x86-64 disassembly via capstone, in Intel syntax, with per-instruction
  annotation of comparisons, conditional branches, call targets, and
  RIP-relative data references.
- Import resolution through the PLT: a `call 0x401050` is labeled `atoi`, read
  out of `.plt`, `.rela.plt`, `.dynsym`, and `.dynstr` the way the loader would.
- Cross-references (who calls this function, what data does it touch) and a
  basic-block control-flow graph for a single function.
- Function discovery in stripped binaries by scanning executable sections for
  the standard function prologue, so a binary with its symbol table removed is
  still navigable.
- Six gradeable challenges over one sample binary, spanning the five core RE
  skills, with solve-then-reveal grading.
- Progress persisted in SQLite behind a small interface, so it swaps cleanly for
  a host application's own store.
- A React web app and a read-only FastAPI, served together for self-hosting with
  one command.

## Quick start

rveng self-hosts. Clone it, bring it up with Docker, open localhost. There is
nothing to configure, no account, no secret, no external service.

```
cd PROJECTS/advanced/rveng
just up
# open http://localhost:8790
```

That builds the React app, has nginx serve it, and runs the FastAPI engine
behind it. To develop with hot-reload instead:

```
just dev-up
# open http://localhost:8791
```

To run the engine's tests and the frontend type check without any server:

```
just test        # uv run pytest -q
just typecheck   # cd frontend && pnpm typecheck
```

## The sample binary

Every example in these docs uses `gate`, a small program compiled with
`gcc -no-pie -fno-stack-protector -O0`. It reads a number from `argv`, compares
it against `1337` in a function called `check`, and prints a secret string when
the number matches. That one binary is enough to teach hex reading, the ELF
skeleton, symbol and string recovery, reading a disassembled gate, patching the
gate, and doing all of it again once the symbols are stripped.

## Where to go next

- `01-CONCEPTS.md` for the reverse-engineering theory and why static analysis
  alone gets you a long way.
- `02-ARCHITECTURE.md` for the one-engine-three-faces design and how a request
  flows through it.
- `03-IMPLEMENTATION.md` for a walk through every engine module against the
  sample binary.
- `04-CHALLENGES.md` for the six challenges, what each teaches, and how to add
  your own.
