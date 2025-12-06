# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 - 2025-12-05

### Added
- **Stack Unwinding**: Full stack trace support with register context preservation at each frame
  - `StackTrace` class for walking the call stack
  - `StackFrame` with complete register state, source location, and local variables
  - Platform-specific unwinding using Windows .pdata/.xdata (RtlVirtualUnwind)
  - Manual fallback unwinding for functions without unwind metadata
  
- **Local Variable Inspection**: Read local variables and function parameters
  - `LocalVariable` type with location information (register, frame-relative, memory)
  - Symbol-based enumeration via DbgHelp (SymEnumSymbols)
  - Support for reading values from registers and stack frames
  - Variable type and size information from debug symbols
  
- **Symbol Resolution**: Enhanced symbol support
  - DbgHelp backend with PDB download from Microsoft symbol server
  - Function name resolution and source line information
  - Symbol lookup by name and address
  - Automatic symbol loading for loaded modules
  
- **Pluggable Unwinders**: Custom stack unwinding interface
  - `Unwinder` abstract interface for runtime-specific unwinding
  - Support for VM bytecode and interpreter frames
  - Unwinders tried in registration order during stack walking
  
- **Process/Thread Abstraction**: First-class debugging objects
  - `Process` class with memory operations and thread enumeration
  - `Thread` class with register access and instruction pointer helpers
  - Primary thread tracking and thread-specific operations
  
- **Enhanced Debugging Features**:
  - Event-based debugging with `waitForEvent()` API
  - Breakpoint classification (initial/loader vs user breakpoints)
  - Process suspend/resume operations
  - Comprehensive debug event logging
  
- **Examples**:
  - `debugger_example` - Updated with command-line arguments
  - `process_api` - Process/Thread abstraction demonstration
  - `stacktrace_example` - Stack unwinding with symbols
  - `locals_example` - Local variable inspection
  
- **Documentation**:
  - Process/Thread abstraction guide
  - Register unwinding implementation details
  - Updated README with new features and examples

### Changed
- Stack frames now use `unique_ptr` for stable frame pointers
- Frame accessors changed to `ip()`, `fp()`, `sp()` methods
- Symbol options configurable before process creation
- Enhanced test harness with stack trace and local variable tests

### Fixed
- Windows backend now properly restores callee-saved registers during unwinding
- Breakpoint classification distinguishes initial loader breakpoint from subsequent system breakpoints
- Frame pointer stability during stack enumeration

## 0.1.0 - 2025-11-27 (initial)
 Project skeleton and initial implementation
 Public API: Debugger class (attach/launch/detach, resume/step, breakpoints)
 Windows backend (basic skeleton/backing simulation) and simulated memory/registers
 Generic C API wrapper (CAPI) for scriptable bindings
 Example program and simple tests
