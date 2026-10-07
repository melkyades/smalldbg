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

void Object::toStream(std::ostream& os, int nested) const {
    if (isImmediate()) { os << immediateString(); return; }
    if (!isValid() || rawOop == 0) { os << "<invalid>"; return; }
    // A heap oop reaching here means the dialect did not route it to its heap
    // object type, which is the only thing that can read the header.
    (void)nested;
    os << "<object>";
}

} // namespace smalltalk
