# SmallDBG — minimal debugger library

SmallDBG is a tiny, cross-platform C++ library that provides a minimal debugger API. This repository contains a working implementation (MIT licensed) with platform-specific back-ends that you can extend and integrate.

The current implementation includes a functional Windows backend using the Debug API and demonstrates how the API can be used from C++ (and how it might be scripted from other languages like Smalltalk via the C API). The public types include an architecture enum (`smalldbg::Arch`) so backends can support x64, arm64 and riscv64 targets.

Features:
- C++ Debugger class with attach/launch/detach, resume/step, breakpoint API
- Functional Windows backend with real process debugging support
- Memory read/write operations
- Register access (x64/ARM64)
- Breakpoint management (set/clear/list)
- **Stack unwinding with full register context** - walk the call stack preserving register state at each frame
- **Local variable inspection** - enumerate and read local variables using debug symbols (PDB/DWARF)
- **Symbol resolution** - function names, source locations, and symbol lookup via DbgHelp (Windows)
- **Pluggable unwinders** - custom stack unwinding for VMs and interpreters
- **Process/Thread abstraction** - first-class Process and Thread objects for clearer debugging code
- Cross-platform CMake build system
- Test harness with test target program

Examples:
- `debugger_example` - Basic debugger operations (launch, breakpoints, registers)
- `process_api` - Process and Thread abstraction usage
- `stacktrace_example` - Stack unwinding with symbol resolution
- `locals_example` - Local variable inspection with stack frames
- `symbols_example` - Symbol provider and source location lookup

Next steps you can take:
- Implement remaining platform backends (Linux ptrace / macOS)
- Add DWARF support for Linux local variable inspection
- Implement watchpoints and hardware breakpoints
- Add your own language bindings via the C API
- Extend test coverage for edge cases

Build (Linux / macOS / Windows with CMake):

1. Create a build directory and configure:

```powershell
mkdir build; cd build
cmake ..
```

2. Build and run the example/test:

```powershell
cmake --build . --config Release

# Run examples
./Release/debugger_example.exe test_target.exe  # Windows
./Release/stacktrace_example.exe test_target.exe
./Release/locals_example.exe test_target.exe

# Run tests
ctest -C Release
```

Quick usage (C++):

```cpp
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"

int main() {
	using namespace smalldbg;
	
	Debugger dbg(Mode::External, Arch::X64);
	dbg.setLogCallback([](const std::string &m){ std::cout << m << std::endl; });
	
	// Enable symbol resolution
	SymbolOptions symOpts;
	symOpts.useSymbolServer = true;  // Download PDBs from Microsoft symbol server
	symOpts.loadLineInfo = true;     // Load source line information
	dbg.setSymbolOptions(symOpts);
	
	// Launch a process for debugging
	dbg.launch("/path/to/exe", {"arg1", "arg2"});
	dbg.waitForEvent(StopReason::ProcessCreated);
	
	// Get the process abstraction
	auto process = dbg.getProcess();
	std::cout << "PID: " << process->getPid() << "\n";
	
	// Set a breakpoint on main
	auto symbols = dbg.getSymbolProvider();
	auto mainSym = symbols->getSymbolByName("main");
	if (mainSym) {
		dbg.setBreakpoint(mainSym->address, "main");
	}
	
	// Resume to breakpoint
	dbg.resume();
	dbg.waitForEvent(StopReason::Breakpoint);
	
	// Get stack trace with local variables
	auto thread = dbg.getCurrentThread();
	StackTrace trace(thread.get());
	trace.unwind();
	
	for (size_t i = 0; i < trace.getFrameCount(); i++) {
		const auto& frame = *trace.getFrames()[i];
		frame.print(std::cout, i);  // Prints function, source location, and locals
	}
	
	// Read/write memory via process
	uint8_t buffer[16];
	process->readMemory(0x400000, buffer, sizeof(buffer));
	
	// Detach when done
	dbg.detach();
}
```

Documentation:
- [Process/Thread Abstraction](docs/ProcessThreadAbstraction.md) - First-class Process and Thread objects
- [Register Unwinding](docs/RegisterUnwinding.md) - Stack unwinding with register context preservation

Scripting / language bindings:
 - The library includes a small C API wrapper header in `include/smalldbg/bindings/CAPI.h` that can be used as a starting point for writing bindings for Smalltalk or other foreign runtimes.

Dependency management:
- If/when third-party dependencies are added to the project, we will use Conan for dependency/version management (conanfile and profiles will be added at that time).

Windows note:
- If CMake selects the Visual Studio generator, pick a matching configuration for your platform (x64/x86/ARM) or use a Makefile-based generator like MinGW or Ninja.
