# SmallDBG — minimal debugger library

SmallDBG is a tiny, cross-platform C++ library that provides a minimal debugger API. This repository contains a working implementation (MIT licensed) with platform-specific back-ends that you can extend and integrate.

The current implementation includes a functional Windows backend using the Debug API and demonstrates how the API can be used from C++ (and how it might be scripted from other languages like Smalltalk via the C API). The public types include an architecture enum (`smalldbg::Arch`) so backends can support x64, arm64 and riscv64 targets.

Features:
- C++ Debugger class with attach/launch/detach, resume/step, breakpoint API
- Functional Windows backend with real process debugging support
- Memory read/write operations
- Register access (x64/ARM64)
- Breakpoint management (set/clear/list)
- Cross-platform CMake build system
- Test harness with test target program

Next steps you can take:
- Implement remaining platform backends (Linux ptrace / macOS)
- Add your own language bindings via the C API
- Extend test coverage for edge cases
- Add more debugging features (watchpoints, symbol resolution, etc.)

Build (Linux / macOS / Windows with CMake):

1. Create a build directory and configure:

```powershell
mkdir build; cd build
cmake ..
```

2. Build and run the example/test:

```powershell
cmake --build . --config Release

# Run example
./Release/example.exe  # Windows
# or
./example  # Linux/macOS

# Run tests
ctest -C Release
```

Quick usage (C++):

```cpp
#include "smalldbg/Debugger.h"

int main() {
	smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
	dbg.setLogCallback([](const std::string &m){ std::cout << m << std::endl; });
	
	// Launch a process for debugging
	dbg.launch("/path/to/exe", {"arg1", "arg2"});
	
	// Set a breakpoint
	dbg.setBreakpoint(0x401000, "entry");
	
	// Resume execution
	dbg.resume();
	
	// Read registers
	smalldbg::Registers regs{};
	if (dbg.getRegisters(regs) == smalldbg::Status::Ok && regs.arch == smalldbg::Arch::X64) {
		std::cout << "RIP=" << std::hex << regs.x64.rip << std::dec << std::endl;
	}
	
	// Read/write memory
	uint8_t buffer[16];
	dbg.readMemory(0x400000, buffer, sizeof(buffer));
	
	// Detach when done
	dbg.detach();
}
```

Smalltalk / scripting notes:
 - The library includes a small C API wrapper header in `include/smalldbg/bindings/CAPI.h` that can be used as a starting point for writing bindings for Smalltalk or other foreign runtimes.

Dependency management:
- If/when third-party dependencies are added to the project, we will use Conan for dependency/version management (conanfile and profiles will be added at that time).

Windows note:
- If CMake selects the Visual Studio generator, pick a matching configuration for your platform (x64/x86/ARM) or use a Makefile-based generator like MinGW or Ninja.
