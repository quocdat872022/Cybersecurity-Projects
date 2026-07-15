<!-- ©AngelaMos | 2026 -->
<!-- 04-no-execution-posture.md -->

# No-Execution Security Posture Research

The single load-bearing security decision for the platform: the backend never
executes any binary. This document enumerates every engine operation and
confirms each is read-only static analysis, and records why patch grading is a
static diff rather than a behavioral test.

## The threat that this design removes

A naive "web app that analyzes binaries" invites users to upload arbitrary
executables that the server then runs or analyzes with tools that themselves
execute code. That path requires sandboxing untrusted native code (containers,
seccomp, resource limits, escape mitigation) and is a large, permanent attack
surface. The platform sidesteps it entirely:

- Challenge binaries are curated and pre-compiled by the author and shipped as
  static assets. Users do not upload binaries to run.
- Every operation the engine performs is reading and parsing bytes, not
  executing them.

If nothing is ever executed, there is no arbitrary-code-execution surface, no
sandbox to escape, and no resource-exhaustion path through a hostile binary.

## Every engine operation is read-only

| Operation | What it does | Executes target? |
|-----------|--------------|------------------|
| hex dump | read bytes, format offset/hex/ascii | no |
| ELF header parse | read fixed-offset fields from bytes | no |
| section/segment walk | read the section/program header tables | no |
| symbol table read | read `.symtab`/`.strtab` bytes | no |
| string extraction | scan bytes for printable runs | no |
| disassembly | capstone decodes bytes to mnemonics | no |
| patch verify | static byte diff of two buffers | no |

Disassembly is decoding, not running: capstone reads instruction bytes and
returns their textual form. It never transfers control to the decoded code.

## Patch grading without execution

The patching module asks the learner to change bytes to alter behavior (for the
sample, flip the `jne` gate so the unlock path always runs). The tempting way to
grade this is to run the patched binary and check its output. That would mean
executing learner-influenced bytes on the server. Rejected.

Instead, each patch challenge ships a known-good patched target alongside the
original. Grading is: apply the learner's submitted bytes at the specified
offset to the original, then compare the result against the known-good patched
target with a static byte diff. Equal means correct. The patched binary is
never run. This grades the exact skill (produce the right byte edit) with zero
execution.

## Input constraints at the API boundary

These are responsibilities of the M2 route layer, not the M1 engine. The engine
grades totally (a malformed submission returns "not correct", never a crash),
but the size and range limits below are enforced where untrusted input enters,
at the API boundary, and are not yet present because the route layer does not
yet exist.

- Analysis routes accept a challenge id, never an arbitrary uploaded binary to
  analyze or run. The binary analyzed is always a curated challenge asset.
- The submit route accepts an answer: a value, a name, or a patched byte range.
  Submitted bytes are only ever diffed, never assembled into something executed.
- Byte inputs will be length-bounded at the route so a submission cannot be an
  arbitrarily large blob. Until M2 lands this bound, the engine still never
  executes the bytes; the open item is DoS size-capping, not code execution.

## The standing rule

Any future feature that would require executing a binary (running a challenge to
observe behavior, an interactive debugger, dynamic analysis) is out of scope by
default. It may be reconsidered only with a separate design that preserves this
posture, most likely by moving execution to an isolated, disposable sandbox that
is explicitly not the analysis backend. Until then: the backend reads bytes, it
does not run them.

## Facts an adversarial check confirmed

- Enumerated every engine operation; all seven are read-only byte processing.
- Confirmed capstone disassembly is pure decoding with no control transfer to
  the target.
- Confirmed patch grading is achievable as a static diff against a known-good
  target, so the one operation that "sounds like" it needs execution does not.
