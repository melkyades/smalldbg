# Webside backends

A [Webside](https://github.com/guillermoamaral/Webside)-compatible HTTP server
that exposes a VM as a REST API, built on the `smalldbg` debugger library.
The Webside IDE frontend talks to it as if it were a Smalltalk image, so class
browsing, the debugger and the inspector all work against a native process, a
crash dump or a Time Travel Debugging trace.

This directory holds what every server shares: the HTTP layer, the route
table, the session that turns a VM's state into Webside documents, and the
`main` every server runs. What a VM actually holds -- its objects, classes and
frames -- is read through the `vmdbg` library beside this one, which knows
nothing about HTTP.

Each VM is a repository of its own, checked out under `vms/` at the root (see
[the root README](../README.md#targets) for how the build finds them). It
brings its `vmdbg` half and its server, and builds one binary:

| Binary | VM | Target |
|---|---|---|
| `webside_egg` | Egg | a live Egg VM process, a dump or a trace |
| `webside_osvm` | OpenSmalltalk / Spur (Cuis, Squeak) | an `.image` file directly, or a live VM, a dump or a trace |

See [DESIGN.md](DESIGN.md) for the architecture and for what adding a VM
involves.

## Building

There is no standalone build here - this directory has no `project()` and links
the `smalldbg` and `vmdbg` targets from the parent. Configure the repository
root and build the target you want; see
[Building from scratch](../README.md#building-from-scratch) for the Conan and
CMake steps.

```bash
cmake --build build-win-x64 --config Release --target webside_osvm
```

## Running

Every server takes its target first and defaults to port 7000, the port
Webside expects. The target is an executable to launch, a crash dump (`.dmp`)
or a TTD trace (`.run`); `--pid N` attaches instead.

```bash
webside_egg  <egg_exe | dump.dmp | trace.run> [options] [-- egg_args...]
webside_osvm <image.image | vm_executable | dump.dmp | trace.run> [options] [-- vm_args...]
```

The options are the same for every server: `--port`, `--pid`, `--workspace`,
`--symbols`, `--source`, `--cwd`, `--pause-ms` and `--verbose`; run a server
with no arguments for what each does.

Egg finds its modules from the directory it starts in, so `webside_egg` is
given `--cwd` with the root of an Egg checkout, and the module to run after
`--`.

`webside_osvm` reads a Spur image straight off disk, with no VM running and
nothing attached, which makes the object model usable on an image alone.
Pointed at a VM executable instead, it launches it, lets it run `--pause-ms`
milliseconds (default 3000) and suspends it to read the heap.

Then point Webside at `http://localhost:7000`.

## API

Routes are registered in `src/WebsideServer.cpp`, and the ones about Smalltalk
objects in `src/Smalltalk/WebsideServer.cpp`; a VM's server may add its own.
Matching is exact first, then longest path-boundary prefix, so
`/classes/Point/methods` reaches the `/classes` handler. Routes marked
*no session* answer before any target is open.

### Session and workspace

| Method | Route | Notes |
|---|---|---|
| GET | `/dialect`, `/version` | which backend this is; *no session* |
| GET | `/debug/state` | whether the target is stopped, running or gone |
| POST | `/debug/suspend` | break into the target |
| GET | `/workspace` | the target and what was set up for it; *no session* |
| GET, POST, DELETE | `/breakpoints` | the workspace's breakpoints; *no session* |
| GET, POST, DELETE | `/labels` | names given to addresses; *no session* |
| POST | `/evaluate` | run an engine command on the target |

### Threads, debuggers and frames

Native threads and the VM's green threads (Smalltalk processes) are listed
together, each with the debugger id the routes below take. A green thread
whose frames the VM's server can rebuild answers these routes the way a native
thread does.

| Method | Route | Notes |
|---|---|---|
| GET | `/threads` | every thread, with its `debuggerId` |
| GET | `/debuggers` | the debugger list |
| GET | `/debuggers/{id}/frames` | backtrace, with each frame's `ip`, `functionAddress`, `framePointer`, `stackPointer`, `module` and `arguments` |
| GET | `/debuggers/{id}/frames/{i}` | one frame's detail; for a Smalltalk frame its class, method, source, receiver, and where in the method it is (`bytecodePC`, `interval`) |
| GET | `/debuggers/{id}/frames/{i}/bindings`, `/registers` | a frame's variables, and its registers; a register the frame does not know has a null value |
| GET | `/debuggers/{id}/stack?frame=[&address=&count=]` | the stack's slots, each with the frame it belongs to and its role |
| POST | `/debuggers/{id}/resume`, `/suspend`, `/terminate` | run control |
| POST | `/debuggers/{id}/runto`, `/reverserunto` | run to an address, forwards or backwards |
| POST | `/debuggers/{id}/reverseresume` | run a trace backwards |
| POST | `/debuggers/{id}/frames/{i}/{action}` | `stepinto`, `stepover`, `stepout`, and the `reverse...` counterparts |

### Traces

| Method | Route | Notes |
|---|---|---|
| GET | `/trace/position` | where the replay is, as `SEQ:STEP`, with the trace's start, end and percent |
| POST | `/trace/position` | move to `{position}`: `SEQ:STEP` in hex, or a percentage such as `50` |
| POST | `/trace/end` | move to the end of the trace |

### Code browsing

| Method | Route | Notes |
|---|---|---|
| GET | `/classes` | all classes |
| GET | `/classes/{name}` | one class |
| GET | `/classes/{name}/{sub}` | `subclasses`, `superclasses`, `variables`, `instance-variables`, `class-variables`, `categories`, `used-categories`, `selectors`, `methods` |
| GET | `/classes/{name}/methods/{selector}` | one method |
| GET | `/classes/{name}/methods/{selector}/bytecodes` | the method's bytecodes, each with its `pc`, `bytes`, `text`, the `selector` a send sends and a jump's `target`; 404 when the VM does not decode them |
| GET | `/search?text=&type=&condition=&ignoreCase=` | `type` defaults to `all`, `condition` to `beginning` |
| POST | `/autocompletions` | completion candidates; *no session* |

### Objects and memory

| Method | Route | Notes |
|---|---|---|
| GET | `/inspect?oop=[&offset=&maxSlots=]` | a heap object, a page of slots at a time; 400 without `oop` |
| GET | `/classoop?oop=` | the class of an object |
| GET | `/retainers?oop=` | the chain of objects that keeps one alive |
| GET | `/memory?address=&count=` | memory laid out as its memory types say: code disassembled, strings, data |
| GET | `/disassemble?address=&count=` | disassembly, with branch targets and operands named |
| GET, POST, DELETE | `/memory-types` | what each address range is shown as; the VM's regions and the modules' sections give the defaults |
| GET | `/regions` | object spaces, code zones, stacks and modules, with what each holds |
| GET | `/classify?address=` | the region, module and symbol holding an address |
| GET | `/symbol?name=` | a native symbol by name |

### Native symbols and types

| Method | Route | Notes |
|---|---|---|
| GET | `/native-symbols?filter=<pattern>` | search native symbols by substring |
| GET | `/native-symbols/{name}` | exact lookup |
| GET | `/native-modules` | loaded executables and shared libraries |
| POST | `/native-modules/{name}/symbols` | load a module's symbols now, rather than when first needed |
| GET | `/native-inspect?expression=<expr>` | walk a C/C++ struct by expression path |

`/native-inspect` takes `<symbol>`, `<symbol>-><field>` (dereference, then
access) or `<symbol>.<field>` (access without dereferencing), chained to any
depth, and answers with the resolved address, value, type and the fields of
that type. It is 400 without an `expression` and 404 when the path does not
resolve.

### Webside UI chrome

`/colors`, `/icons`, `/themes`, `/logo`, `/extensions`, `/usual-categories`,
`/command-definitions`, `/stats` and `/objects` answer fixed documents, so the
frontend can render itself.
