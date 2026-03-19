# Webside Debugger Example

This example demonstrates how to debug an Egg Smalltalk VM using the Webside IDE protocol.

## How it works

1. **Launch Egg Under Debugger**: Starts Egg Smalltalk directly under the debugger
2. **Resume and Initialize**: Lets Egg run for 2 seconds to complete initialization
3. **Suspend for Debugging**: Suspends execution so the debugger is ready
4. **Start Webside Server**: HTTP server starts on port 7000 (configurable)
5. **Debug via IDE**: Connect your Webside IDE to remotely debug the Egg process

## Building

```bash
cd build
cmake --build . --config Release --target webside_egg
```

## Usage

Basic usage (uses default Egg path):
```bash
./Release/webside_egg
```

With custom Egg path:
```bash
./Release/webside_egg "/path/to/egg"
```

With custom Egg path and port:
```bash
./Release/webside_egg "/path/to/egg" 8080
```

## Connecting with Webside IDE

Once the server is running, you'll see:
```
=== Webside Server Ready ===
Debugging Egg Smalltalk (PID: 12345)
Webside API available at: http://localhost:7000
```

In your Webside IDE:
1. Add a new backend connection
2. Use the URL: `http://localhost:7000`
3. The dialect should auto-detect as "Egg"
4. You can now inspect frames, objects, and control execution

## Available API Endpoints

### Webside Standard API
- `GET /dialect` - Returns "Egg"
- `GET /version` - Returns version info
- `GET /debuggers` - List active debuggers
- `GET /debuggers/1/frames` - Get stack frames with locals
- `POST /debuggers/1/objects/describe` - Describe an object by handle
- `POST /debuggers/1/resume` - Resume execution
- `POST /debuggers/1/terminate` - Detach from process

### Custom Debug Control
- `POST /debug/suspend` - Suspend the running process
- `POST /debug/resume` - Resume execution
- `POST /debug/step` - Single step instruction
- `GET /debug/state` - Get current debugger state
- `GET /debug/registers` - Get current register values
- `POST /debug/breakpoint/set` - Set a breakpoint
- `POST /debug/breakpoint/clear` - Clear a breakpoint
- `GET /debug/breakpoints` - List all breakpoints
- `POST /debug/memory/read` - Read memory
- `GET /debug/event` - Poll for debug events

## Example Workflow

1. Start the webside_egg server
2. The Egg process launches and is suspended
3. Connect Webside IDE to http://localhost:7000
4. View the stack frames in the IDE
5. Inspect Egg objects by their handles
6. Resume, suspend, or step through execution
7. Set breakpoints as needed

## Architecture

```
┌─────────────────┐
│  Webside IDE    │
│  (Browser)      │
└────────┬────────┘
         │ HTTP API
         ▼
┌─────────────────┐
│  webside_egg    │
│  HTTP Server    │
├─────────────────┤
│ DebugSession    │
│ EggInspector    │
└────────┬────────┘
         │ smalldbg API
         ▼
┌─────────────────┐
│  smalldbg       │
│  Debugger       │
└────────┬────────┘
         │ win dbg api / win dbgeng api /ptrace / task_for_pid
         ▼
┌─────────────────┐
│      egg        │
│ (Smalltalk VM)  │
└─────────────────┘
```

## Notes

- The Egg process is initially suspended and ready for debugging
- All Egg stack frames are visible with Smalltalk method names
- Object inspection works for Egg object handles
- The server runs until you press Ctrl+C
- When the server exits, it detaches from the Egg process
