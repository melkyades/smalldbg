#pragma once

#include "Backend.h"
#include "../../include/smalldbg/Snapshot.h"

#include <vector>

namespace smalldbg {

/** A target that is only memory: regions read from files or given as bytes,
 *  at the addresses they appear at. It never runs and has no threads, so it
 *  is stopped for as long as it is open, and everything but reading memory is
 *  refused. **/
class SnapshotBackend : public Backend {
public:
    using Backend::Backend;

    Status openSnapshot(const std::vector<SnapshotRegion>& regions) override;

    Status attach(uintptr_t pid) override;
    Status launch(const std::string& path, const std::vector<std::string>& args,
                  const std::string& workingDir) override;
    Status detach() override;

    Status resume() override { return Status::NotSupported; }
    Status step(Thread*) override { return Status::NotSupported; }
    Status stepOver(Thread*) override { return Status::NotSupported; }
    Status stepOut(Thread*) override { return Status::NotSupported; }
    Status suspend() override { return Status::NotSupported; }

    Status setBreakpoint(Address, const std::string&) override { return Status::NotSupported; }
    Status clearBreakpoint(Address) override { return Status::NotSupported; }
    std::vector<Breakpoint> listBreakpoints() const override { return {}; }

    Status readMemory(Address address, void* outBuf, size_t size) const override;
    Status writeMemory(Address, const void*, size_t) override { return Status::NotSupported; }
    Status getRegisters(Thread*, Registers&) const override { return Status::NotSupported; }
    Status recoverCallerRegisters(Registers&) const override { return Status::NotSupported; }

    bool isAttached() const override { return opened; }
    StopReason getStopReason() const override { return StopReason::None; }
    bool isStopped() const override { return opened; }
    Address getStopAddress() const override { return 0; }

    // Nothing ever happens to a snapshot, so there is never an event to wait for.
    StopReason waitForEvent(StopReason, int) override { return StopReason::None; }

private:
    struct Region {
        Address address;
        std::vector<uint8_t> bytes;
        Address end() const { return address + bytes.size(); }
    };

    Status load(const SnapshotRegion& given, Region& into) const;
    const Region* regionAt(Address address) const;

    std::vector<Region> regions;  // sorted by address, none overlapping
    bool opened{false};
};

} // namespace smalldbg
