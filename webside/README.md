# Webside C++ Backend for Egg Smalltalk

This is a Webside backend server that uses the `smalldbg` library to provide debugging capabilities for Egg Smalltalk processes through a REST API.

## Building

```bash
cd webside
mkdir build
cd build
cmake ..
cmake --build . --config Debug
```

## Running

```bash
./Debug/webside-server.exe [port]
```

Default port is 7000 (Webside standard port).

## API Endpoints

### Health Check
- `GET /` - Returns server status

### Debug Control
- `POST /debug/launch` - Launch Egg Smalltalk process
  - Body: `{"path": "egg.exe"}`
- `POST /debug/attach` - Attach to existing process
  - Body: `{"pid": 1234}`
- `POST /debug/detach` - Detach from process
- `POST /debug/resume` - Resume execution
- `POST /debug/suspend` - Suspend/break execution at current point
- `POST /debug/step` - Single step instruction
- `GET /debug/state` - Get current debugger state
- `GET /debug/event` - Wait for debug event (1s timeout)

### Registers & Memory
- `GET /debug/registers` - Get all CPU registers
- `POST /debug/memory/read` - Read memory
  - Body: `{"address": "0x12345678", "size": 256}`

### Breakpoints
- `POST /debug/breakpoint/set` - Set breakpoint
  - Body: `{"address": "0x12345678", "name": "optional name"}`
- `POST /debug/breakpoint/clear` - Clear breakpoint
  - Body: `{"address": "0x12345678"}`
- `GET /debug/breakpoints` - List all breakpoints

### Native Symbols
- `GET /native-symbols?filter=<pattern>` - Search native symbols by substring
  - Response: `[{"name": "main", "address": "0x100003f40", "size": 128, "type": "function", "module": "egg"}]`
- `GET /native-symbols/<name>` - Look up a specific symbol by exact name
  - Response: `{"name": "main", "address": "0x100003f40", "size": 128, "type": "function", "module": "egg"}`
- `GET /native-modules` - List all loaded modules (executables and shared libraries)
  - Response: `[{"path": "/usr/lib/libc.dylib", "name": "libc.dylib", "loadAddress": "0x...", "endAddress": "0x...", "symbolCount": 1234}]`

### Native Type Inspection
- `GET /native-inspect?expression=<expr>` - Inspect C/C++ struct fields by traversing an expression path
  - Expression syntax: `<symbol>` or `<symbol>-><field>-><field>...` or `<symbol>.<field>.<field>...`
  - `->` dereferences a pointer then accesses a field
  - `.` accesses a field directly (no dereference)
  - Example: `Egg::debugRuntime->_evaluator->_context`
  - Response:
    ```json
    {
      "expression": "Egg::debugRuntime->_evaluator",
      "address": "0x00000001026dd280",
      "value": "0x00000001026de190",
      "type": "Egg::Evaluator *",
      "kind": "pointer",
      "size": 8,
      "fields": [
        {"name": "_runtime", "type": "Egg::Runtime *", "kind": "pointer", "offset": 8, "size": 8},
        {"name": "_context", "type": "Egg::EvaluationContext *", "kind": "pointer", "offset": 16, "size": 8}
      ]
    }
    ```
  - Errors: 400 if `expression` query param missing, 404 if expression cannot be resolved

## Integration with Webside

Configure your Webside instance to connect to `http://localhost:7000`

## Notes

- Currently supports x64 Windows only
- Created to debug Smalltalk VMs but can debug any x64 process
- Uses event-driven debugging with proper synchronization
