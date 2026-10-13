#include "HeapObject.h"

#include <smalldbg/Debugger.h>

#include <algorithm>
#include <sstream>

namespace smalltalk {

namespace {

// Enough of a collection to be worth showing, not so much that one slot fills
// the pane.
constexpr int kMaxRenderedElements = 32;
constexpr size_t kMaxRenderedStringLength = 32;

} // namespace

uint64_t HeapObject::rawSlotAt(int index) const {
    if (index < 0) return 0;
    uint64_t value = 0;
    uint64_t address = bodyAddress() + static_cast<uint64_t>(index) * slotSize();
    if (dbg->readMemory(address, &value, slotSize()) != smalldbg::Status::Ok) return 0;
    return value;
}

std::vector<uint8_t> HeapObject::bytes(int from, int count) const {
    if (!isValid()) return {};
    uint32_t total = size();
    if (from < 0 || static_cast<uint32_t>(from) >= total) return {};
    uint32_t available = total - static_cast<uint32_t>(from);
    uint32_t wanted = count < 0 ? available
                                : std::min<uint32_t>(available, static_cast<uint32_t>(count));
    std::vector<uint8_t> out(wanted);
    uint64_t address = bodyAddress() + static_cast<uint64_t>(from);
    if (wanted && dbg->readMemory(address, out.data(), wanted) != smalldbg::Status::Ok) return {};
    return out;
}

std::string HeapObject::bytesAsString() const {
    auto raw = bytes();
    return std::string(raw.begin(), raw.end());
}

std::string HeapObject::className() const {
    auto behavior = classObject();
    if (!behavior || !behavior->isValid()) return {};
    return behavior->classNameIfClass();
}

bool HeapObject::isKindOf(const std::string& name, int maxDepth) const {
    auto behavior = classObject();
    for (int depth = 0; depth < maxDepth && behavior && behavior->isValid(); depth++) {
        if (behavior->classNameIfClass() == name) return true;
        behavior = behavior->superclassObject();
    }
    return false;
}

// A byte object holds text far more often than it holds data, and the two
// classes that always do are worth quoting the way source would.
void HeapObject::renderBytes(std::ostream& os, const std::string& name) const {
    std::string text = bytesAsString();
    if (name == "Symbol") { os << "#" << text; return; }
    if (name == "String") {
        if (text.size() > kMaxRenderedStringLength)
            text = text.substr(0, kMaxRenderedStringLength) + "...";
        os << "'" << text << "'";
        return;
    }
    os << withArticle(name);
}

void HeapObject::renderSlots(std::ostream& os, const std::string& name,
                             int nested) const {
    int count = static_cast<int>(size());
    if (nested <= 0) {
        os << name << "(" << count << ")";
        return;
    }
    int shown = std::min(count, kMaxRenderedElements);
    os << "(";
    for (int i = 0; i < shown; i++) {
        if (i > 0) os << " ";
        auto element = slotObjectAt(i);
        if (element) element->toStream(os, nested - 1);
    }
    if (count > shown) os << " ...+" << (count - shown);
    os << ")";
}

void HeapObject::toStream(std::ostream& os, int nested) const {
    if (!isValid()) { os << "<invalid>"; return; }

    std::string name;
    try { name = className(); } catch (...) {}
    if (name.empty()) { os << "an unknown Object"; return; }

    if (renderSpecial(os, name, nested)) return;

    // A class prints as its name, which its metaclass's name starts with.
    const std::string suffix = " class";
    if (name.size() > suffix.size()
        && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
        std::string own = classNameIfClass();
        if (!own.empty()) { os << own; return; }
    }

    if (name == "UndefinedObject") { os << "nil"; return; }
    if (name == "True")            { os << "true"; return; }
    if (name == "False")           { os << "false"; return; }

    if (isBytes()) { renderBytes(os, name); return; }

    if (name == "Array") { renderSlots(os, name, nested); return; }

    if (name == "Association" && nested > 0 && size() >= 2) {
        auto key = slotObjectAt(0);
        auto value = slotObjectAt(1);
        if (key && value) {
            key->toStream(os, nested - 1);
            os << " -> ";
            value->toStream(os, nested - 1);
            return;
        }
    }

    os << withArticle(name);
}

} // namespace smalltalk
