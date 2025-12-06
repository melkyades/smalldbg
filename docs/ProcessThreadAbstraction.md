# Process and Thread Abstraction

## Overview

The `Process` and `Thread` classes provide a cross-platform, object-oriented abstraction for debugged processes and their threads. These objects know about the debugger and can answer queries directly.

## Design Philosophy

Instead of calling methods on the debugger with PIDs and thread IDs:
```cpp
debugger.getRegisters(regs);  // Which thread?
debugger.readMemory(addr, buf, size);  // Which process?
```

You work with first-class Process and Thread objects:
```cpp
auto process = debugger.getProcess();
auto thread = process->currentThread();
thread->getRegisters(regs);  // Clear: this thread's registers
thread->readMemory(addr, buf, size);  // Clear: via this thread's process
```

## API

### Process Class

```cpp
class Process {
    // Process identification
    int getPid() const;
    
    // Thread enumeration
    std::vector<std::shared_ptr<Thread>> threads();
    std::optional<std::shared_ptr<Thread>> getThread(ThreadId tid);
    std::optional<std::shared_ptr<Thread>> currentThread();
    
    // Memory operations
    Status readMemory(Address address, void* outBuf, size_t size) const;
    Status writeMemory(Address address, const void* data, size_t size);
    
    // State
    bool isAttached() const;
    StopReason getStopReason() const;
    bool isStopped() const;
    Address getStopAddress() const;
};
```

### Thread Class

```cpp
class Thread {
    // Thread identification
    ThreadId getThreadId() const;
    Process* getProcess() const;
    
    // Register access
    Status getRegisters(Registers& out) const;
    
    // Memory access (convenience - delegates to process)
    Status readMemory(Address address, void* outBuf, size_t size) const;
    Status writeMemory(Address address, const void* data, size_t size);
    
    // Stack inspection helpers
    Address getInstructionPointer() const;
    Address getStackPointer() const;
    Address getFramePointer() const;
};
```

## Usage Example

```cpp
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"

using namespace smalldbg;

Debugger dbg(Mode::External);
dbg.attach(pid);

// Get the process object
auto process = dbg.getProcess();

// Suspend and inspect
dbg.suspend();
dbg.waitForEvent(StopReason::None, 1000);

// Get current thread
auto thread = process->currentThread();
if (thread) {
    // Direct queries on thread object
    std::cout << "IP: 0x" << std::hex << (*thread)->getInstructionPointer() << "\n";
    std::cout << "SP: 0x" << std::hex << (*thread)->getStackPointer() << "\n";
    
    // Read registers
    Registers regs{};
    (*thread)->getRegisters(regs);
    
    // Read memory via thread
    uint64_t value;
    (*thread)->readMemory((*thread)->getStackPointer(), &value, sizeof(value));
}

// Enumerate all threads
for (const auto& t : process->threads()) {
    std::cout << "Thread " << t->getThreadId() << "\n";
}
```

## Benefits

1. **Clear Ownership**: Thread objects know their process, process knows its debugger
2. **Type Safety**: Can't accidentally mix thread IDs from different processes
3. **Convenience**: Helper methods like `getInstructionPointer()` hide architecture details
4. **Extensibility**: Easy to add process/thread-specific operations
5. **Cross-Platform**: Same API works on Windows, Linux, macOS (when implemented)
