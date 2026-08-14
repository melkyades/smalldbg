# SmallDBG Coding Style

C++20, MSVC / GCC / Clang.  Keep things simple and readable.

## Naming

| Element         | Convention            | Example                         |
|-----------------|-----------------------|---------------------------------|
| Class / Struct  | PascalCase            | `StackFrame`, `SymbolProvider`  |
| Enum type       | PascalCase            | `StopReason`, `InitMode`        |
| Enum value      | PascalCase            | `SingleStep`, `ProcessExit`     |
| Function/Method | camelCase             | `getRegisters`, `attachedPid`   |
| Variable        | camelCase             | `stopReason`, `threadMap`       |
| Member variable | camelCase, no prefix/suffix | `attached`, `stopAddress`  |
| Constant        | camelCase or UPPER    | `pointerSize`, (macros: UPPER)  |
| Namespace       | lowercase             | `smalldbg`                      |
| File            | PascalCase            | `StackTrace.cpp`, `Backend.h`   |
| Type alias      | PascalCase            | `Address`, `ThreadId`           |

**No** `m_`, `_` prefix, or `_` suffix on member variables.

When a constructor or setter parameter would shadow a member, shorten the
parameter name instead of decorating the member:

```cpp
// Good
Process(Debugger* dbg, uintptr_t p) : debugger(dbg), pid(p) {}
void setOptions(const SymbolOptions& opts) { options = opts; }

// Bad
Process(Debugger* dbg, uintptr_t pid_) : debugger(dbg), pid(pid_) {}
```

## Layout

- `#pragma once` for header guards.
- One blank line between function definitions.
- Opening brace on the same line as the declaration.
- `namespace smalldbg {` ... `} // namespace smalldbg` — contents not indented.

```cpp
namespace smalldbg {

class Foo {
public:
    void bar();

private:
    int count{0};
};

} // namespace smalldbg
```

## Headers

- Public API headers live in `include/smalldbg/`.
- Internal headers live next to their `.cpp` files (`src/`, `src/backends/`, etc.).
- Include paths from internal sources use relative paths:
  `#include "../../include/smalldbg/Types.h"`.
- Group includes: same-module headers first, then project headers, then
  standard library, then platform headers.

## Classes

- Access specifiers in order: `public`, then `protected`, then `private`.
- Virtual destructors via `~Foo() override = default;` in derived classes.
- Use `override` on every overridden method.
- Prefer `= default` / `= delete` over empty bodies.

## Types & Memory

- `uintptr_t` for process IDs (pointer-sized).
- `uint64_t` (`Address`) for memory addresses.
- `uint64_t` (`ThreadId`) for thread identifiers.
- `std::shared_ptr` for objects shared across subsystems (`Process`, `Thread`).
- `std::unique_ptr` for sole-ownership objects (`SymbolBackend`, `StackFrame`).
- Raw pointers for non-owning back-references (`Debugger*`, `Process*`).
- Aggregate initialization with `{}`: `bool stopped{false};`

Prefer a reference to a pointer.  A reference parameter states that the
argument is always there, so the callee never checks it; keep a pointer
only where absence is a real state.  Existing signatures are fine as they
are - convert them when the code is being touched anyway.

```cpp
// Good - non-null is in the type
void process(StackFrame& frame, Debugger& debugger);

// Bad - invites a null check that can never fire
void process(StackFrame* frame, Debugger* debugger);
```

For something that may be absent, return a raw pointer.  `std::optional`
holds values; `std::optional<T&>` is a C++26 addition and does not compile
here, and `std::optional<std::reference_wrapper<T>>` buys nothing for the
`.get()` it costs at every use.

```cpp
StackFrameProcessor* processorFor(...);        // nullptr when none matches
std::optional<Symbol> getSymbolByAddress(Address addr);   // a value
```

## RAII & Null Checks

Use RAII for all resource management.  If a resource is acquired in a
constructor, it is released in the destructor — never rely on manual
cleanup calls.

```cpp
// Good — unique_ptr releases automatically
std::unique_ptr<DbgEngEventCallbacks> eventCallbacks;

// Bad — manual new/delete
DbgEngEventCallbacks* eventCallbacks = nullptr;
// ... somewhere later: delete eventCallbacks;
```

**Avoid checking member variables for null** when their lifetime is
guaranteed by the class invariant.  If a member is set in the constructor
or in an init method that must succeed before anything else runs, treat it
as always valid — a null check is dead code and obscures the actual contract.

```cpp
// Good — debugger is set in the constructor, always valid
Status Backend::doWork() {
    return debugger->readMemory(addr, buf, size);
}

// Bad — unnecessary defensive check
Status Backend::doWork() {
    if (!debugger) return Status::Error;   // can never be null
    return debugger->readMemory(addr, buf, size);
}
```

Null checks **are** appropriate when:
- The member is legitimately absent during part of the object's lifetime
  (e.g. `process` before `initProcess()` is called).
- The pointer comes from an external/optional source (callback, user input).
- The object is in a partially-constructed or shutting-down state by design.

For platform handles (HANDLE, HMODULE, COM pointers), wrap them in a
small RAII helper or use `std::unique_ptr` with a custom deleter rather
than scattering `CloseHandle` / `Release` calls.

```cpp
// Good — RAII wrapper for a Win32 handle
struct HandleCloser {
    void operator()(HANDLE h) const { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;
```

## Functions

- Short getters / one-liners may be inline in the class body.
- Pass large objects by `const&`.  Return small structs by value.
- Use `std::optional` for values that may be absent.
- Functions that set up a resource return `Status`.
- When a parameter is unused, cast to void: `(void)param;`
  or use unnamed parameter: `void foo(int /*unused*/)`.

One loop per function.  A loop inside a loop is two functions: name the
inner one and hand it the element.  A loop body should ideally be a single
call taking the element, plus whatever else that call needs.

```cpp
// Good
void StackTrace::appendInlinedFrames(const StackFrame& physical, Address ip,
                                     const std::vector<InlineFrameInfo>& inlined,
                                     size_t maxFrames) {
    for (const auto& one : inlined) {
        if (frames.size() >= maxFrames) break;
        frames.push_back(inlinedFrameFor(physical, ip, one));
    }
}
```

Check for failure and return early.  Never put the work in an `else`: the
happy path stays at one level of indentation no matter how many ways the
call can fail.

```cpp
// Good
auto control5 = queryInterface<IDebugControl5>(control);
if (!control5) return;
auto symbols4 = queryInterface<IDebugSymbols4>(symbols);
if (!symbols4) return;
// ... the work, unindented

// Bad
if (control5) {
    if (symbols4) {
        // ... the work, buried
    }
}
```

## Error Handling

- No exceptions.  Use `Status` enum returns.
- HRESULT-based Windows/COM calls: check with `FAILED(hr)`.
- Log errors via the `log` callback, never `std::cerr`.

## Concurrency

- Name mutexes descriptively: `stopMutex`, `bpMutex`, `initMutex`.
- Use `std::lock_guard` or `std::unique_lock` — never manual lock/unlock.
- Condition variables paired with their mutex by name convention
  (`stopMutex` / `stopCV`, `initMutex` / `initCv`).

## Backend Architecture

- `Backend` is the abstract base class.  Concrete backends (`WindowsBackend`,
  `DbgEngBackend`, `PtraceBackend`) override its pure virtuals.
- Common state lives in `Backend`: `process`, `debugger`, `mode`, `arch`,
  `log`, `eventCallback`.
- Backend-specific state stays in the concrete class.
- Process creation goes through `Backend::initProcess(pid)`.

## Miscellaneous

- C++20 standard (`std::optional`, structured bindings, `if constexpr`, etc.).
- Build system: CMake (minimum 3.15).
- No RTTI.  No exceptions.  Keep dependencies minimal.
- Prefer `enum class` over plain `enum`.
- Comments: `//` for single-line, `///` for doc/Doxygen-style.
