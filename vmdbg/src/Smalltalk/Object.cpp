#include "Object.h"
#include "HeapObject.h"

#include <sstream>

namespace smalltalk {

std::string articleFor(const std::string& className) {
    if (className.empty()) return "a";
    switch (className[0]) {
        case 'A': case 'a': case 'E': case 'e': case 'I': case 'i':
        case 'O': case 'o': case 'U': case 'u':
            return "an";
        default:
            return "a";
    }
}

std::string withArticle(const std::string& className) {
    return articleFor(className) + " " + className;
}

std::string Object::immediateString() const {
    if (isSmallInteger()) return std::to_string(smallIntegerValue());
    if (isCharacter()) {
        uint32_t code = characterValue();
        if (code >= 32 && code < 127)
            return std::string("$") + static_cast<char>(code);
        return "Character value: " + std::to_string(code);
    }
    if (isSmallFloat()) {
        std::ostringstream os;
        os << smallFloatValue();
        return os.str();
    }
    return {};
}

std::string Object::printString() const {
    std::ostringstream os;
    toStream(os, 2);
    return os.str();
}

std::unique_ptr<HeapObject> Object::asBaseHeapObject() const {
    return nullptr;
}

// Only the dialect's heap object can read a header, so a heap oop asks it.
std::string Object::className() const {
    if (isSmallInteger()) return "SmallInteger";
    if (isCharacter()) return "Character";
    if (isHeapObject())
        if (auto heap = asBaseHeapObject()) return heap->className();
    return {};
}

void Object::toStream(std::ostream& os, int nested) const {
    if (isImmediate()) { os << immediateString(); return; }
    if (isHeapObject()) {
        if (auto heap = asBaseHeapObject()) { heap->toStream(os, nested); return; }
    }
    os << "<invalid>";
}

} // namespace smalltalk
