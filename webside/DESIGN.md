# Webside Backend Design

## Overview

The Webside backend provides a REST API that allows remote debugging and
inspection of a language VM. It sits on two libraries: `smalldbg` for the
process, its memory and its symbols, and **`vmdbg`** for what those bytes mean
to the runtime that wrote them -- its objects, classes, frames and processes.

The split matters: `vmdbg` answers in values and knows nothing about HTTP or
JSON, so a state reporter, or a front end for a language that is not
Smalltalk, reads a VM through it without taking Webside along. Everything in
this directory is the part that turns those answers into documents.

Code is shared at the highest layer that can hold it: what any debugger needs
is in `smalldbg`, what any VM needs in `vmdbg`, what any Smalltalk needs in
their Smalltalk layers, and a VM's repository holds only what is its own. A
VM's server adds to the shared documents through hooks; it does not keep a
copy of them.

## Architecture

### Components

1. **HttpServer** - Lightweight HTTP/1.1 server with route registration,
   query-string parsing, and URL decoding.
2. **WebsideServer** - Base class that sets up the common Webside REST routes
   (classes, methods, debuggers, frames, memory, traces, ...) and answers them
   out of the session its **Workspace** has open. `smalltalk::WebsideServer`
   adds the routes about Smalltalk objects, such as `/retainers`.
3. **Workspace** - What the developer set up: which target to open and how to
   reach it, plus what they accumulate while working (breakpoints, address
   labels). There is one of these; a VM is not a kind of workspace, only the
   kind of session it builds, which it hands over as a factory.
4. **Session** - One connection to one process, trace or dump, in three layers.
   `vmdbg::VMSession` opens the target, moves it and answers what the runtime
   holds; `webside::WebsideSession` derives from it and turns those answers
   into Webside documents; `smalltalk::Session` adds what every Smalltalk
   has: class browsing, objects, Smalltalk frames and green threads. Run
   control lives in the first and is written once for every VM: there is no
   Smalltalk way to resume a process. A VM says only what goes stale when the
   target moves (`beforeTargetRuns`, `targetMayHaveMoved`) and what it wants
   read again once it stops (`afterTargetStops`).
5. **Inspector** - A VM's reader of object headers, classes, methods and
   processes. `vmdbg::VMInspector` maps memory into regions;
   `smalltalk::Inspector` adds the class table, method sources and bytecodes,
   and what keeps an object alive. It answers in values; the rendering of
   those values is in `Smalltalk/InspectorJson` and the sessions.
6. **Frame unwinder** - `smalltalk::FrameUnwinder` walks the frames a VM
   builds, recovers from a broken link, and attaches a `FrameMetadata` (class,
   selector, method, receiver, arguments) to each frame it names. A VM gives
   it its frame layout.

### Stack Frames: Native vs Smalltalk

Every frame, native or Smalltalk, is a `smalldbg::StackFrame` in one
`StackTrace`, so the same routes answer for both:

#### Native Frames
- **Source**: Resolved via DWARF / PDB debug info when available; the detail
  shows the function's source with the line marked.
- **Arguments**: Those the debug info lists, with the engine's text for each
  value.
- **Registers**: All of them for the frame a thread stopped in; a caller's
  frame knows only the ip, sp and fp unwinding recovered.

#### Smalltalk Frames
- **Recognised by**: the `FrameMetadata` the VM's unwinder attached.
- **Detail**: the class, the method with its source (a block's selector says
  which block), the receiver, and where in the method the frame is:
  `bytecodePC` and the source `interval` a client marks.
- **Arguments**: named by the selector's keywords; a block's are numbered.
- **Bindings**: receiver, arguments and temporaries, named by parsing the
  method's source.

#### Green threads

A VM's processes (green threads) are listed with the native threads. A
running one is shown through the native thread running it. A parked one, whose
frames the VM saved somewhere else, is answered like a native thread when the
VM rebuilds its frames (`readGreenFrames`); the session keeps that trace until
the processes are read again, once for each place the target stops.

### Integration with smalldbg

All memory access, breakpoints, stepping, trace navigation and stack
unwinding go through the `smalldbg` library:

```cpp
// Stack unwinding
auto thread = debugger->getCurrentThread();
smalldbg::StackTrace trace(thread.get());
trace.unwind(maxFrames);

// Memory reads
uint64_t value;
process->readMemory(address, &value, sizeof(value));

// Trace replay
auto position = debugger->tracePosition();
debugger->seekTrace(50.0);
```

## API Design

### Stack Frame JSON

```json
{
  "index": 1,
  "label": "Array>>at:put:",
  "ip": "0x100400010",
  "functionAddress": "0x100400000",
  "functionOffset": 16,
  "framePointer": "0x7ff7bfeff8a0",
  "stackPointer": "0x7ff7bfeff860",
  "arguments": [{ "name": "index", "value": "0x3", "printString": "1" }]
}
```

The detail of a Smalltalk frame adds `class`, `method`, `receiver`,
`hasSource`, and, when the VM can place the frame, `bytecodePC` and
`interval` (`start` and `end`, counted in characters from 1).

### Object Descriptor JSON

```json
{
  "oop": "0x100200000",
  "class": "Array",
  "size": 3,
  "value": "an Array(1 2 3)",
  "slots": [
    { "index": 0, "raw": "0x3", "type": "SmallInteger", "value": 1 },
    { "index": 1, "raw": "0x5", "type": "SmallInteger", "value": 2 }
  ]
}
```

See [README.md](README.md#api) for every route.

## Adding a VM

A VM is a repository of its own, checked out under `vms/<name>` at the root. It
holds two halves and a `CMakeLists.txt` that builds them:

In `vmdbg/Smalltalk/<Name>/`, what the VM is:

1. `<Name>Inspector`, a `smalltalk::Inspector` that reads the VM's object
   layout, class table and processes, plus the object model it reads through
   (`<Name>Object`, `<Name>HeapObject`, `<Name>KnownObjects`). It may decode
   methods' bytecodes (`bytecodesOf`).
2. A `smalltalk::FrameUnwinder` subclass, if the platform unwinder cannot
   follow the VM's frames on its own.

In `webside/`, what it answers:

3. `<Name>DebugSession`, a `smalltalk::Session`. It opens the target
   (`onTargetOpened`), reads the processes (`readGreenThreads`,
   `readGreenFrames`), and adds what only it knows through hooks such as
   `describeHeader`, `addDialectFrameDetail`, `framePosition` and
   `addMemoryTypeDefaults`.
4. `<Name>WebsideServer`, for any routes of its own.
5. A `main.cpp` that names the VM and the session it builds, and hands them to
   `webside::runWebside`, the `main` every server shares.

Not every VM needs a live process. OSVM reads an OpenSmalltalk image through a
`SpurMemory` interface with two backends, one over the `.image` file and one
over `smalldbg`, so the whole object model runs with no target attached. A VM
whose heap is self-describing on disk can do the same.

## References

- `smalldbg::StackTrace` - Native stack unwinding with symbols
- `smalldbg::SymbolProvider` - Symbol resolution for modules
- `smalldbg::Thread::getStackTrace()` - Per-thread stack traces
- `vmdbg::VMSession`, `smalltalk::Session` - the hooks a VM implements
