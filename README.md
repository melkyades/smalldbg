# SmallDBG — minimal debugger library (barebones)

SmallDBG is a tiny, cross-platform C++ library that provides a minimal debugger API. This repository contains a barebones skeleton implementation (MIT licensed) so you can extend, integrate, and wire platform-specific back-ends later.

This initial implementation contains a minimal Windows backend (skeleton) and demonstrates how the API will be used from C++ (and how it might be scripted from other languages like Smalltalk via the C API). The public types now include an architecture enum (`smalldbg::Arch`) so backends can support x64, arm64 and riscv64 targets.

Features in this barebones update:
- Minimal C++ Debugger class with attach/launch/detach, resume/step, breakpoint API
- Minimal Windows backend (simulated behaviour for now) and a tiny test program
- Cross-platform CMake build

Next steps you can take:
- Implement remaining platform backends (Linux ptrace / macOS / additional Windows features)
- Add Smalltalk language bindings via the C API where needed
- Add more tests and integration harnesses

Build (Linux / macOS / Windows with CMake):

1. Create a build directory and configure:

```powershell
mkdir build; cd build
cmake ..
```

2. Build and run the example/test:

```powershell
cmake --build . --config Release
.
# Run example
./example
# Run tests
ctest -V
```

Quick usage (C++):

```cpp
#include "smalldbg/Debugger.h"

int main() {
	smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
	dbg.setLogCallback([](const std::string &m){ std::cout << m << std::endl; });
	dbg.launch("/path/to/exe");
	dbg.setBreakpoint(0x401000, "entry");
	// resume/step/read/write/getRegisters etc.

	smalldbg::Registers regs{};
	if (dbg.getRegisters(regs) == smalldbg::Status::Ok && regs.arch == smalldbg::Arch::X64) {
		std::cout << "RIP=" << std::hex << regs.x64.rip << std::dec << std::endl;
	}
}
```

Smalltalk / scripting notes:
 - The library includes a small C API wrapper header in `include/smalldbg/bindings/CAPI.h` that can be used as a starting point for writing bindings for Smalltalk or other foreign runtimes.

Dependency management:
- If/when third-party dependencies are added to the project, we will use Conan for dependency/version management (conanfile and profiles will be added at that time).

Windows note:
- If CMake selects the Visual Studio generator, pick a matching configuration for your platform (x64/x86/ARM) or use a Makefile-based generator like MinGW or Ninja.
