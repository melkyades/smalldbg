# SmallDBG — minimal debugger library

SmallDBG is a tiny, cross-platform C++ library that provides a minimal debugger API. This repository contains a working implementation (MIT licensed) with platform-specific back-ends that you can extend and integrate.

The library ships with platform backends for Windows (Win32 Debug API, DbgEng/WinDbg engine with TTD support), macOS (ptrace + Mach APIs), and Linux (ptrace + /proc), symbol backends for PDB (DbgHelp/DbgEng), Mach-O, and ELF, and can be used from C++ or scripted from other languages via the C API. A target's architecture is an `smalldbg::Arch` object (`X86`, `X64` or `ARM64`), which knows its pointer size, its registers and how to name its flags.

On top of the library sit two more: `vmdbg/`, for debugging virtual machines, and `webside/`, which serves a debugging session over the [Webside](https://github.com/guillermoamaral/Webside) protocol. Each VM is a repository of its own, checked out under `vms/`.

Features:
- C++ Debugger class with attach/launch/detach, resume/step/suspend, run to an address, breakpoint API
- Windows backends: Win32 Debug API and DbgEng engine (with Time Travel Debugging)
- macOS backend: ptrace + Mach VM/thread APIs. Every stop comes through a Mach exception server, and symbols are read from the target's memory, so the libraries of the dyld shared cache have them too
- Linux backend: ptrace + /proc filesystem
- **Crash dumps and TTD traces** - open a `.dmp` or a `.run`; replay a trace backwards and forwards, ask where the replay is and how far the trace runs, move to a position or a percentage, and find when an address last ran
- Memory read/write operations, and each loaded module's sections from its image headers
- **Registers by architecture** (x86, x64, ARM64) - a caller's frame reports only the ip, sp and fp unwinding recovers
- Breakpoint management (set/clear/list)
- **Stack unwinding with full register context** - walk the call stack preserving register state at each frame, including inlined frames and the WoW64 system-call thunk
- **Local variables and arguments** - enumerate and read a frame's locals and arguments using debug symbols (PDB/DWARF)
- **Symbol resolution** - function names, source locations, and symbol lookup via DbgHelp/DbgEng (Windows), Mach-O (macOS), and ELF (Linux)
- **Disassembly** (Capstone) - with `DisassemblyAnnotator` naming branch targets, data operands and what a memory slot holds
- **DWARF type inspection** - parse DWARF5 debug info from .o files to inspect C/C++ struct fields via expression paths
- **Pluggable unwinders** - custom stack unwinding for VMs and interpreters
- **Process/Thread abstraction** - first-class Process and Thread objects for clearer debugging code
- **VM debugging library** (`vmdbg/`) - a `VMSession` opens a launched, attached, dumped or traced VM; a `VMInspector` maps its memory into regions and memory types; the Smalltalk layer reads class tables, objects, frames, green threads (Smalltalk processes), method sources and their message sends, and what keeps an object alive
- **Webside servers** (`webside/`) - one REST server per VM, exposing run control, trace navigation, stacks, registers, memory listings, object inspection, class browsing, method bytecodes and native symbols. See [webside/README.md](webside/README.md)
- **Reports** (`vmreport/`) - a library for writing reports out of dumps
- Cross-platform CMake build system
- Test harness with test target program, plus unit, live and performance-budget tests

Examples:
- `example` - Basic debugger operations (launch, breakpoints, registers)
- `process_api` - Process and Thread abstraction usage
- `stacktrace_example` - Stack unwinding with symbol resolution
- `locals_example` - Local variable inspection with stack frames
- `symbols_example` - Symbol provider and source location lookup
- `ttd_replay` - Opening a TTD trace and replaying it

Next steps you can take:
- Implement watchpoints and hardware breakpoints
- Add your own language bindings via the C API
- Extend test coverage for edge cases

## Building from scratch

The build is CMake driven, and dependencies come from [Conan 2](https://conan.io).
`CMakeLists.txt` calls `find_package(capstone)` and the test targets link
`doctest`, so **CMake cannot configure until Conan has generated a toolchain**.
There are three steps in every case: `conan install`, `cmake` configure,
`cmake --build`.

### Prerequisites

| | |
|---|---|
| CMake | 3.15+ (3.23+ if you want to use the generated presets) |
| Conan | 2.x, on `PATH` (a pip install lands it in `~/.local/bin`) |
| Windows | Visual Studio 2019 Build Tools (toolset v142) + a Windows SDK |
| Linux / macOS | any C++20 compiler; Ninja or Make |

Dependencies are declared in `conanfile.txt`: `capstone/5.0.6` (disassembly),
`cpp-httplib/0.47.0` (the Webside servers' HTTP layer) and `doctest/2.4.11`
(tests). Conan builds and caches them on first use.

One-time setup, if you have never run Conan on this machine:

```bash
conan profile detect
```

### Windows, x64

```bash
conan install . --output-folder=build-win-x64 --build=missing \
    -s build_type=Release -s arch=x86_64

cmake -S . -B build-win-x64 -G "Visual Studio 16 2019" -A x64 \
    -DCMAKE_TOOLCHAIN_FILE=build-win-x64/conan_toolchain.cmake

cmake --build build-win-x64 --config Release
ctest --test-dir build-win-x64 -C Release
```

### Windows, x86

Same thing with the architecture switched in both tools. A 32-bit target has to
be debugged by a 32-bit build, so this is not optional if that is what you are
pointing the debugger at:

```bash
conan install . --output-folder=build-win-x86 --build=missing \
    -s build_type=Release -s arch=x86

cmake -S . -B build-win-x86 -G "Visual Studio 16 2019" -A Win32 \
    -DCMAKE_TOOLCHAIN_FILE=build-win-x86/conan_toolchain.cmake

cmake --build build-win-x86 --config Release
```

After changing shared code under `src/` or `webside/src/`, build **both**
architectures before calling it done. The two trees compile the same sources
against different pointer widths, so code that is clean in one can fail to
compile in the other, and only a rebuild of that tree will tell you.

### Linux / macOS

Single-config generators need the build type in both tools, not just in Conan:

```bash
conan install . --output-folder=build --build=missing -s build_type=Release

cmake -S . -B build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build
ctest --test-dir build
```

On macOS a process may debug another only when it is signed with the
debugger entitlement in `debugger.entitlements`. The build signs every
executable that launches or attaches to a target, ad hoc, as it links it
(`smalldbg_sign_as_debugger` in the root `CMakeLists.txt`); Developer Mode
must be on (`DevToolsSecurity -status`). A target signed with the hardened
runtime and without `get-task-allow` cannot be debugged.

macOS keeps port 7000, the servers' default, for its AirPlay Receiver. Pass
another with `--port`, or turn the receiver off in System Settings.

### Always pass `--output-folder`

A bare `conan install .` writes `conan_toolchain.cmake`, the generated
`capstone-*.cmake` files, the `conanbuild`/`conanrun` env scripts and a
`CMakePresets.json` whose `binaryDir` is the source root **into the repository
root**. They are all gitignored and nothing is broken by them, but a relative
`-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake` then silently picks up whichever
architecture that stray copy was generated for. Point every `conan install` at
the build directory it belongs to.

### Presets

Each `conan install` also appends its build directory to `CMakeUserPresets.json`.
With one build directory you can shorten configure and build to:

```bash
cmake --preset conan-default
cmake --build --preset conan-release
```

With several, every included file declares a preset named `conan-default`, and
CMake refuses to read any of them:

```
CMake Error: Could not read presets from /tmp/smalldbg:
Duplicate preset: "conan-default"
```

So once you build both Windows architectures (`build-win-x86` and
`build-win-x64` both listed), use the explicit commands above.

### Targets

| Target | What it is |
|---|---|
| `smalldbg` | the debugger library |
| `vmdbg` | the VM debugging library, with its Smalltalk layer |
| `webside_common` | the Webside server and session every VM's server is built on |
| `vmreport` | the report-writing library |
| `example`, `process_api`, `symbols_example`, `stacktrace_example`, `locals_example`, `ttd_replay` | examples in `examples/` |
| `unit_tests`, `live_tests`, `perf_tests`, `test_target` | library tests (`ctest`) |
| `vmdbg_tests`, `webside_tests`, `vmreport_tests` | tests of the layers above |
| `webside_egg` | Webside HTTP server for the Egg VM (from `vms/egg`) |
| `webside_osvm` | Webside HTTP server for OpenSmalltalk/Spur images such as Cuis and Squeak (from `vms/osvm`) |
| `osvm_image_test` | Spur object-model tests, run against an image file with no debugger attached |

Each VM lives in a repository of its own. The build adds every entry of `vms/`
that is a checkout with a `CMakeLists.txt`, as a directory or a symlink to one,
or a `<name>.path` file holding the checkout's path, absolute or relative to
`vms/`, where symlinks are awkward. A VM with neither is simply left out, so
the library builds and tests without any.

Run an example or a server directly from its configuration directory:

```powershell
./build-win-x64/examples/Release/stacktrace_example.exe test_target.exe
./build-win-x64/vms/osvm/Release/webside_osvm.exe <image.image> --port 7000
```

Every server takes the same options after its target, which may be an
executable to launch, a crash dump or a TTD trace:

| Option | |
|---|---|
| `--port N` | HTTP port (default 7000, or a bare number) |
| `--pid N` | attach to a running process |
| `--workspace FILE` | breakpoints, labels and symbol paths; defaults to `<target>.workspace.json` for a dump or a trace |
| `--symbols PATH` | extra directories to look for pdbs in |
| `--source DIR` | where the target's sources are |
| `--cwd DIR` | the directory a launched target starts in; by default its executable's folder on Windows, the server's own elsewhere |
| `--pause-ms N` | let a launched target run this long before suspending it |
| `-v`, `--verbose` | log what the session is doing |

Quick usage (C++):

```cpp
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"

int main() {
	using namespace smalldbg;
	
	Debugger dbg(Mode::External, X64::instance());
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
- [Webside backends](webside/README.md) - The servers, their routes and how a VM plugs in
- [Webside design](webside/DESIGN.md) - How the layers fit together

Scripting / language bindings:
 - The library includes a small C API wrapper header in `include/smalldbg/bindings/CAPI.h` that can be used as a starting point for writing bindings for Smalltalk or other foreign runtimes.

Dependency management:
- Conan 2 owns third-party dependencies; they are pinned in `conanfile.txt` and reach CMake through the generated toolchain. See [Building from scratch](#building-from-scratch).

Windows note:
- The Visual Studio generator is multi-config, so the configuration is chosen at build time (`--build ... --config Release`), and binaries land in a `Release/` subdirectory of each target's directory. Pass the platform at configure time with `-A x64` / `-A Win32`, matching the `arch` you gave Conan; mixing the two produces link errors against the Conan packages.
