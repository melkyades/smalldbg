#include "ObjectNamer.h"

#include <map>
#include <mutex>

namespace smalltalk {

namespace {

std::map<smalldbg::Debugger*, ObjectNamer>& namers() {
    static std::map<smalldbg::Debugger*, ObjectNamer> registry;
    return registry;
}

std::mutex& guard() {
    static std::mutex mutex;
    return mutex;
}

} // namespace

void setObjectNamer(smalldbg::Debugger* debugger, ObjectNamer namer) {
    std::lock_guard<std::mutex> lock(guard());
    namers()[debugger] = std::move(namer);
}

std::string objectName(smalldbg::Debugger* debugger, uint64_t oop) {
    ObjectNamer namer;
    {
        std::lock_guard<std::mutex> lock(guard());
        auto found = namers().find(debugger);
        if (found == namers().end()) return {};
        namer = found->second;
    }
    return namer ? namer(oop) : std::string{};
}

} // namespace smalltalk
