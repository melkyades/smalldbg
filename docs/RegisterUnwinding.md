# Register Unwinding for Local Variables

## Overview

To properly support local variable inspection in stack traces, we need to restore the register context at each frame during unwinding. This is necessary because:

1. **Arguments** may be passed in registers (rcx, rdx, r8, r9 on x64 Windows)
2. **Local variables** may be stored in callee-saved registers
3. **DWARF location expressions** reference registers to describe where variables are stored

## Current Implementation

### Basic Register Capture

Each `StackFrame` now includes:
```cpp
struct StackFrame {
    // ... existing fields ...
    Registers registers;      // Full register context at this frame
    bool hasRegisters;        // Whether context is valid
};
```

### Frame-by-Frame Register State

During unwinding, we:
1. Start with current thread's registers (frame 0)
2. Save full register state to each frame
3. Update IP, BP, SP when moving to next frame
4. Attempt to restore callee-saved registers (currently limited)

### Current Limitations

**Without unwind metadata**, we can only reliably track:
- **RIP** (instruction pointer) - read from stack (return address)
- **RBP** (frame pointer) - read from stack (saved rbp)
- **RSP** (stack pointer) - computed from frame pointer

**We CANNOT currently restore**:
- Callee-saved registers (rbx, r12-r15, rdi, rsi)
- Argument registers (rcx, rdx, r8, r9) 
- Volatile registers (rax, r10, r11, etc.)

This means **local variable inspection is limited** without additional metadata.

## Complete Solution: Unwind Information

To properly restore all registers, we need platform-specific unwind metadata:

### Windows: .pdata and .xdata sections

**Exception Directory (.pdata)**:
- Array of `RUNTIME_FUNCTION` entries
- Maps code addresses to unwind info

**Unwind Info (.xdata)**:
- Describes prologue/epilogue operations
- Specifies which registers are saved and where
- Provides frame pointer usage information

**API**: `RtlLookupFunctionEntry()` and `RtlVirtualUnwind()`

### Linux/DWARF: Call Frame Information (CFI)

**DWARF .eh_frame / .debug_frame**:
- CFA (Canonical Frame Address) rules
- Register save locations relative to CFA
- Unwind instructions for each code address

**API**: `libunwind` or manual DWARF parsing

## Implementation Plan

### Phase 1: Windows Unwind Data ✅ (Partial)

1. ✅ Add `Registers` to `StackFrame`
2. ✅ Capture initial register state
3. ✅ Update IP/BP/SP during unwinding
4. ⏳ **TODO**: Use `RtlLookupFunctionEntry()` to find unwind info
5. ⏳ **TODO**: Use `RtlVirtualUnwind()` to restore all registers

### Phase 2: DWARF Support (Future)

1. Parse .eh_frame / .debug_frame sections
2. Implement DWARF expression evaluator
3. Restore registers using CFI rules
4. Support for Linux/POSIX platforms

### Phase 3: Local Variable Access

Once registers are properly unwound:

1. **Read DWARF location descriptors** for variables
2. **Evaluate location expressions**:
   - `DW_OP_fbreg`: Offset from frame base (RBP)
   - `DW_OP_reg*`: Value in register
   - `DW_OP_breg*`: Offset from register value
3. **Read variable values** from memory/registers
4. **Type information** for proper display

## Example: Windows RtlVirtualUnwind

```cpp
bool StackTrace::restoreX64RegistersWindows(Address ip, Registers& regs, Debugger* debugger) {
    // Look up unwind info for this IP
    DWORD64 imageBase = 0;
    RUNTIME_FUNCTION* func = RtlLookupFunctionEntry(ip, &imageBase, NULL);
    
    if (!func) {
        // No unwind info - leaf function or missing data
        return false;
    }
    
    // Prepare context for unwinding
    CONTEXT context = {};
    context.Rip = regs.x64.rip;
    context.Rsp = regs.x64.rsp;
    context.Rbp = regs.x64.rbp;
    // ... copy all registers from regs to context ...
    
    // Virtual unwind to previous frame
    PVOID handlerData = NULL;
    DWORD64 establisherFrame = 0;
    
    RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        imageBase,
        context.Rip,
        func,
        &context,
        &handlerData,
        &establisherFrame,
        NULL
    );
    
    // Update our register structure with unwound values
    regs.x64.rip = context.Rip;
    regs.x64.rsp = context.Rsp;
    regs.x64.rbp = context.Rbp;
    regs.x64.rbx = context.Rbx;
    regs.x64.rdi = context.Rdi;
    regs.x64.rsi = context.Rsi;
    regs.x64.r12 = context.R12;
    regs.x64.r13 = context.R13;
    regs.x64.r14 = context.R14;
    regs.x64.r15 = context.R15;
    
    return true;
}
```

## Example: Accessing Local Variables

Once proper unwinding is implemented:

```cpp
// Get stack trace with full register context
StackTrace* trace = thread->getStackTrace();

for (const auto& frame : trace->getFrames()) {
    // Get variable location from DWARF
    // Example: local variable at [rbp-16]
    Address varAddr = frame.registers.x64.rbp - 16;
    
    uint64_t value;
    debugger->readMemory(varAddr, &value, sizeof(value));
    
    // Or: variable in r12 register
    uint64_t regValue = frame.registers.x64.r12;
}
```

## Testing

Current state can be tested with:
```bash
./stacktrace_example.exe ./test_target.exe
```

Each frame now has a `registers` field containing the register state, but only IP/BP/SP are accurate without unwind metadata.

## References

- [x64 Calling Convention (Windows)](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Exception Handling (x64)](https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [DWARF Call Frame Information](http://dwarfstd.org/doc/DWARF5.pdf) (Section 6.4)
- [libunwind](https://www.nongnu.org/libunwind/)
- [RtlVirtualUnwind](https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlvirtualunwind)
