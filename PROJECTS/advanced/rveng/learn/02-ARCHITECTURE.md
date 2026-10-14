<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# Architecture

rveng is one analysis engine with three faces. The engine is framework-free
Python that knows nothing about HTTP or React. A thin FastAPI layer adapts it to
the web. A React app consumes that API. Progress is persisted behind a small
interface so it can be swapped. This shape exists so the engine and the lesson
content can be lifted out of this project and mounted inside a larger
application without dragging a web framework along.

## One engine, three faces

```
                         +--------------------------+
                         |   rveng/engine/  (pure)  |
                         |  elf disasm plt xref cfg  |
                         |  hex strings patch discover|
                         |  challenge (grading)      |
                         +------------+--------------+
                                      |
             +------------------------+------------------------+
             |                        |                        |
        +----+-----+           +------+------+          +------+------+
        | HTTP API |           |   library   |          |     CLI     |
        | FastAPI  |           |  (import it)|          | (potential) |
        +----+-----+           +-------------+          +-------------+
             |
        +----+-----+
        | React app|
        +----------+
```

The engine is the product. The API is an adapter. The React app is a face. The
same engine that answers `/api/challenges/05-find-the-gate/disasm` could be
imported directly by CertGames and driven with no HTTP at all. Nothing in
`rveng/engine/` imports FastAPI, and nothing renders HTML. That separation is the
whole point.

## The engine modules

Each module is small and does one thing against raw bytes. None of them execute
anything.

```
engine/elf.py       parse the ELF64 header, sections, and symbols from bytes
engine/hex.py       render a canonical offset/hex/ascii dump
engine/strings.py   scan bytes for printable runs
engine/disasm.py    decode x86-64 with capstone, annotate the interesting ops
engine/plt.py       resolve a PLT stub address to an imported symbol name
engine/xref.py      collect cross-references from decoded instructions
engine/cfg.py       split a function into basic blocks and connect them
engine/discover.py  find functions in a stripped binary by prologue scan
engine/patch.py     apply and diff byte edits, verify a patch statically
engine/challenge.py the challenge model and the solve-then-reveal grader
```

The dependency direction is strict: everything depends on `elf.py` and its byte
buffer, `disasm.py` feeds `xref.py` and `cfg.py`, and `challenge.py` depends on
`patch.py` for patch grading. Nothing points back up toward the API.

## The API layer

`rveng/api/` is the adapter. It loads the curated challenges once at startup,
exposes read-only analysis of them, and grades submissions.

```
api/app.py        builds the FastAPI app and defines every route
api/store.py      loads challenges from disk; the progress store (Protocol + impls)
api/schemas.py    the Pydantic response and request shapes
api/limits.py     size and length caps for untrusted input
api/middleware.py a body-size cap enforced before the body is parsed
api/server.py     the ASGI entry point (create_app())
```

The routes are deliberately boring. Given a challenge id they return a hex view,
an ELF summary, a disassembly, a control-flow graph, cross-references, or the
string list. One route accepts a submission and grades it. No route accepts a
binary to analyze; the only binaries in the system are the curated challenge
assets.

## How a request flows

Take a learner disassembling the `check` function of the sample:

```
browser
  GET /api/challenges/05-find-the-gate/disasm?symbol=check
    |
  nginx  (serves the React app, proxies /api to the API container)
    |
  FastAPI route in app.py
    |  look up the challenge by id  (store.py)
    |  parse its binary            (elf.ElfImage)
    |  find the symbol "check"     (image.symbol)
    |  disassemble the symbol      (disasm.disassemble_symbol)
    |  resolve any call names      (plt.plt_map)
    |  serialize to schemas.DisasmView
    v
  JSON back to the browser, rendered by the disasm pane
```

The engine did the analysis; the API only translated ids to calls and objects to
JSON. Crucially, the gate-highlight annotation on the disassembly is withheld
until the challenge is solved, so a learner sees honest raw disassembly first and
the "this is the gate" hint only after they have found it themselves.

## Progress behind an interface

Progress (which challenges a session has solved) is the one piece of state. It
lives behind a `ProgressStore` protocol with two methods:

```
mark_solved(session, challenge_id) -> None
solved(session) -> set[str]
```

Two implementations satisfy it: `InMemoryProgress` (a dict, used in tests) and
`SqliteProgress` (a file-backed table, the default the server runs). The routes
only ever see the protocol, so swapping the backing store is a one-line change in
`create_app` and touches no route. When rveng is extracted into a host
application, that application points the same protocol at its own database, and
nothing else moves.

```
routes ---> ProgressStore (protocol)
                 |
        +--------+---------+
        |                  |
  InMemoryProgress    SqliteProgress    (host app plugs its own here)
```

## The deployment topology

rveng self-hosts on localhost with Docker. There is no cloud, no TLS, no domain,
no account. Two containers in production:

```
PROD (compose.yml, project "rveng")        DEV (dev.compose.yml, project "rveng-dev")

  browser :8790                              browser :8791
      |                                          |
  [ nginx ]  serves built React dist         [ nginx ]  proxies everything
      |  /api                                    |  /        |  /api
  [ api ]  uvicorn (FastAPI engine)          [ vite HMR ] [ api ] uvicorn --reload
      |                                                        |
  rveng_data volume (sqlite progress)                    rveng_data_dev volume
```

nginx serves the compiled frontend and proxies `/api` to the API container. The
API is a pure engine adapter that never learns to serve a SPA, which keeps it
extractable. In development, nginx fronts the Vite dev server for hot reload
instead of serving a static build. The two projects use structural-literal names
(`rveng` and `rveng-dev`), so dev and prod are namespace-isolated by
construction and cannot collide. Everything runs on built-in defaults, so a clean
clone comes up with no configuration.

## Extraction into a host application

The end state this architecture buys: mounting rveng as a feature elsewhere means
importing `rveng.engine`, reusing the challenge assets as-is, pointing the
`ProgressStore` protocol at the host's store, and mounting the self-contained
React components. The engine and content come along unchanged. That is the
difference between building a throwaway project and building a feature that
happens to also stand alone.
