#pragma once

#include "../../include/smalldbg/Types.h"
#include <functional>
#include <vector>
#include <optional>

namespace smalldbg {

struct Breakpoint;
struct Registers;

class Backend {
public:
    Backend(Mode m, Arch a) : mode(m), arch(a) {}
    virtual ~Backend() = default;

    virtual Status attach(int pid) = 0;
    virtual Status launch(const std::string &path, const std::vector<std::string> &args) = 0;
    virtual Status detach() = 0;

    virtual Status resume() = 0;
    virtual Status step() = 0;

    virtual Status setBreakpoint(Address addr, const std::string &name) = 0;
    virtual Status clearBreakpoint(Address addr) = 0;
    virtual std::vector<Breakpoint> listBreakpoints() const = 0;

    virtual Status readMemory(Address address, void *outBuf, size_t size) const = 0;
    virtual Status writeMemory(Address address, const void *data, size_t size) = 0;
    virtual Status getRegisters(Registers &out) const = 0;

    virtual bool isAttached() const { return false; }
    virtual std::optional<int> attachedPid() const { return std::nullopt; }

    void setLogCallback(std::function<void(const std::string &)> cb) { log = std::move(cb); }

protected:
    Mode mode{Mode::External};
    Arch arch{Arch::X64};
    std::function<void(const std::string &)> log;
};

} // namespace smalldbg
