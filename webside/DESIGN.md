# Webside Backend Design

## Overview

The Webside backend provides a REST API that allows remote debugging and
inspection of a language VM using the `smalldbg` native debugger library.
Each VM dialect (Egg, Bee, …) implements a thin adapter layer on top of
shared infrastructure.

## Architecture

### Components

1. **HttpServer** – Lightweight HTTP/1.1 server with route registration,
   query-string parsing, and URL decoding.
2. **WebsideServer** – Base class that sets up the common Webside REST routes
   (classes, methods, workspaces, evaluations, debuggers, …) and delegates
   VM-specific behaviour to a **DebugSession** subclass.
3. **DebugSession** – Abstract interface for debugger lifecycle, frame
   listing, object inspection, and stepping control.  Each dialect provides
   a concrete implementation (e.g. `EggDebugSession`).
4. **Inspector** – Per-dialect helper that reads VM object headers, walks
   green-thread stacks, and formats Smalltalk values for the REST API.

### Stack Frames: Native vs Smalltalk

The stack trace distinguishes two kinds of frames:

#### Native Frames
- **Type**: `native`
- **Language**: `C++`
- **Source**: Resolved via DWARF / PDB debug info when available.
- **Bindings**: Registers (IP / FP / SP) plus DWARF local variables.

#### Smalltalk Frames
- **Type**: `smalltalk`
- **Language**: `Smalltalk`
- **Location**: Within the VM's compiled-code region.
- **Bindings**: receiver (`self`), arguments, and temporaries extracted
  from the green-thread stack.  Argument / temp names are recovered by
  parsing the method header source code.

### Integration with smalldbg

All memory access, breakpoints, stepping, and stack unwinding go through
the `smalldbg` library:

```cpp
// Stack unwinding
auto thread = debugger->getCurrentThread();
smalldbg::StackTrace trace(thread.get());
trace.unwind(maxFrames);

// Memory reads
uint64_t value;
process->readMemory(address, &value, sizeof(value));
```

Stepping variants (step into, step over, step out) and their reverse-debug
counterparts set temporary breakpoints at the caller's return address and
resume execution.

## API Design

### Stack Frame JSON

```json
{
  "index": 1,
  "type": "smalltalk",
  "label": "Array>>at:put:",
  "language": "Smalltalk",
  "ip": "0x100400000"
}
```

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

### VM Inspector Routes

In addition to the standard Webside debugger routes, each dialect can
expose low-level inspector endpoints:

| Route           | Description                                  |
|-----------------|----------------------------------------------|
| GET /regions    | Code zones, stack, and loaded modules        |
| GET /classify   | Classify an address (module, stack, symbol)   |
| GET /inspect    | Inspect a heap object by OOP                 |
| GET /memory     | Read typed memory (bytes, string, intN)      |
| GET /symbol     | Look up a native symbol by name              |
| GET /disassemble| Disassemble native code at an address        |

## Adding a New Dialect

1. Create a subdirectory under `webside/src/<Dialect>/`.
2. Implement `<Dialect>DebugSession` (subclass of `DebugSession`).
3. Implement `<Dialect>Inspector` for object layout / green-thread walking.
4. Implement `<Dialect>WebsideServer` (subclass of `WebsideServer`),
   adding any dialect-specific routes.
5. Add a `CMakeLists.txt` with a platform guard if needed.

5. **DWARF Type Database** (`DwarfTypes.h/cpp`)
   - Parses DWARF5 debug info from `.o` files referenced by N_OSO stab entries in the Mach-O binary
   - Supports standalone `.o` files and `.a` archive members (BSD extended names)
   - Extracts struct/class/union types with fields, pointer/typedef chains, base types, and global variable-to-type mappings
   - Provides `findType(name)` and `getVariableTypeName(name)` for type lookup
   - Expression evaluator in `EggWebsideServer` walks `->` and `.` accessors, reading pointer values from process memory to resolve multi-level paths
   - Map bytecode offsets to source locations
   - Show method selectors in stack traces

5. **Advanced Object Inspection**
   - Recognize special object formats (ByteArray, String, etc.)
   - Display object contents appropriately
   - Handle circular references

6. **Enhanced Frame Extraction**
   - Implement proper bytecode context analysis
   - Extract all arguments and temporaries
   - Show bytecode instruction pointer within method

## Example Usage

```javascript
// Launch Bee Smalltalk
POST /debug/launch { "path": "BeeDev.exe" }

// Configure runtime (manually for now)
POST /debug/runtime/configure {
  "codeStart": "0x140000000",
  "codeEnd": "0x140100000",
  "heapStart": "0x200000000",
  "heapEnd": "0x300000000"
}

// Get stack frames (will classify as Smalltalk vs Native)
GET /debuggers/1/frames

// Inspect an object
POST /debuggers/1/objects/describe { "handle": "0x200001000" }
```

## References

- `smalldbg::StackTrace` - Native stack unwinding with symbols
- `smalldbg::SymbolProvider` - Symbol resolution for modules
- `smalldbg::Thread::getStackTrace()` - Per-thread stack traces
- Bee Smalltalk object format (internal VM documentation)
