#include "Json.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace webside {

// =========================================================================
// Construction
// =========================================================================

Json::Json() : type(Type::Null) {}

Json Json::object() {
    Json j;
    j.type = Type::Object;
    return j;
}

Json Json::array() {
    Json j;
    j.type = Type::Array;
    return j;
}

Json Json::string(const std::string& s) {
    Json j;
    j.type = Type::String;
    j.strVal = s;
    return j;
}

Json Json::number(int n) {
    Json j;
    j.type = Type::Int;
    j.intVal = n;
    return j;
}

Json Json::number(int64_t n) {
    Json j;
    j.type = Type::Int;
    j.intVal = n;
    return j;
}

Json Json::number(uint32_t n) {
    Json j;
    j.type = Type::Int;
    j.intVal = static_cast<int64_t>(n);
    return j;
}

Json Json::number(double d) {
    Json j;
    j.type = Type::Double;
    j.doubleVal = d;
    return j;
}

Json Json::boolean(bool b) {
    Json j;
    j.type = Type::Bool;
    j.boolVal = b;
    return j;
}

Json Json::null() { return Json(); }

Json Json::hex(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08x", v);
    return Json::string(buf);
}

Json Json::hex(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%016llx",
                  static_cast<unsigned long long>(v));
    return Json::string(buf);
}

// =========================================================================
// Object mutators
// =========================================================================

Json& Json::set(const std::string& key, const Json& val) {
    fields.emplace_back(key, val);
    return *this;
}

Json& Json::set(const std::string& key, const std::string& val) {
    return set(key, Json::string(val));
}

Json& Json::set(const std::string& key, const char* val) {
    return set(key, Json::string(val));
}

Json& Json::set(const std::string& key, int val) {
    return set(key, Json::number(val));
}

Json& Json::set(const std::string& key, int64_t val) {
    return set(key, Json::number(val));
}

Json& Json::set(const std::string& key, uint32_t val) {
    return set(key, Json::number(val));
}

Json& Json::set(const std::string& key, bool val) {
    return set(key, Json::boolean(val));
}

Json& Json::set(const std::string& key, std::nullptr_t) {
    return set(key, Json::null());
}

// =========================================================================
// Array mutators
// =========================================================================

Json& Json::add(const Json& val) {
    items.push_back(val);
    return *this;
}

Json& Json::add(const std::string& val) { return add(Json::string(val)); }
Json& Json::add(const char* val)        { return add(Json::string(val)); }
Json& Json::add(int val)                { return add(Json::number(val)); }
Json& Json::add(int64_t val)            { return add(Json::number(val)); }
Json& Json::add(bool val)               { return add(Json::boolean(val)); }

// =========================================================================
// Accessors
// =========================================================================

static const Json nullSingleton;

const Json& Json::operator[](const std::string& key) const {
    if (type != Type::Object) return nullSingleton;
    for (auto& kv : fields) {
        if (kv.first == key) return kv.second;
    }
    return nullSingleton;
}

const Json& Json::operator[](size_t index) const {
    if (type != Type::Array || index >= items.size()) return nullSingleton;
    return items[index];
}

std::string Json::asString() const {
    if (type == Type::String) return strVal;
    if (type == Type::Int) return std::to_string(intVal);
    if (type == Type::Double) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%g", doubleVal);
        return buf;
    }
    if (type == Type::Bool) return boolVal ? "true" : "false";
    return "";
}

int64_t Json::asInt() const {
    if (type == Type::Int) return intVal;
    if (type == Type::Double) return static_cast<int64_t>(doubleVal);
    if (type == Type::String) {
        // Handle hex strings like "0x1234"
        if (strVal.size() > 2 && strVal[0] == '0' && (strVal[1] == 'x' || strVal[1] == 'X'))
            return static_cast<int64_t>(std::strtoull(strVal.c_str() + 2, nullptr, 16));
        return std::strtoll(strVal.c_str(), nullptr, 10);
    }
    if (type == Type::Bool) return boolVal ? 1 : 0;
    return 0;
}

uint64_t Json::asUInt() const {
    if (type == Type::Int) return static_cast<uint64_t>(intVal);
    if (type == Type::Double) return static_cast<uint64_t>(doubleVal);
    if (type == Type::String) {
        if (strVal.size() > 2 && strVal[0] == '0' && (strVal[1] == 'x' || strVal[1] == 'X'))
            return std::strtoull(strVal.c_str() + 2, nullptr, 16);
        return std::strtoull(strVal.c_str(), nullptr, 10);
    }
    return 0;
}

double Json::asNumber() const {
    if (type == Type::Double) return doubleVal;
    if (type == Type::Int) return static_cast<double>(intVal);
    if (type == Type::String) return std::strtod(strVal.c_str(), nullptr);
    return 0.0;
}

bool Json::asBool() const {
    if (type == Type::Bool) return boolVal;
    if (type == Type::Int) return intVal != 0;
    if (type == Type::String) return !strVal.empty();
    return false;
}

bool Json::isNull()   const { return type == Type::Null; }
bool Json::isObject() const { return type == Type::Object; }
bool Json::isArray()  const { return type == Type::Array; }
bool Json::isString() const { return type == Type::String; }
bool Json::isNumber() const { return type == Type::Int || type == Type::Double; }
bool Json::isBool()   const { return type == Type::Bool; }

// =========================================================================
// Queries
// =========================================================================

bool Json::empty() const {
    switch (type) {
        case Type::Null:   return true;
        case Type::Array:  return items.empty();
        case Type::Object: return fields.empty();
        default:           return false;
    }
}

size_t Json::size() const {
    switch (type) {
        case Type::Array:  return items.size();
        case Type::Object: return fields.size();
        default:           return 0;
    }
}

const std::vector<Json>& Json::elements() const { return items; }

const std::vector<std::pair<std::string, Json>>& Json::entries() const {
    return fields;
}

// =========================================================================
// Serialization
// =========================================================================

std::string Json::dump() const {
    std::string out;
    out.reserve(256);
    appendTo(out);
    return out;
}

void Json::appendTo(std::string& out) const {
    switch (type) {
        case Type::Null:
            out += "null";
            break;
        case Type::Bool:
            out += boolVal ? "true" : "false";
            break;
        case Type::Int:
            out += std::to_string(intVal);
            break;
        case Type::Double: {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%g", doubleVal);
            out += buf;
            break;
        }
        case Type::String:
            out += '"';
            appendEscaped(out, strVal);
            out += '"';
            break;
        case Type::Array:
            out += '[';
            for (size_t i = 0; i < items.size(); i++) {
                if (i > 0) out += ',';
                items[i].appendTo(out);
            }
            out += ']';
            break;
        case Type::Object:
            out += '{';
            for (size_t i = 0; i < fields.size(); i++) {
                if (i > 0) out += ',';
                out += '"';
                appendEscaped(out, fields[i].first);
                out += "\":";
                fields[i].second.appendTo(out);
            }
            out += '}';
            break;
    }
}

void Json::appendEscaped(std::string& out, const std::string& s) {
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20)
                    out += ' ';
                else
                    out += static_cast<char>(c);
        }
    }
}

std::string Json::escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 10);
    appendEscaped(out, s);
    return out;
}

// =========================================================================
// Parsing
// =========================================================================

Json Json::parse(const std::string& text) {
    const char* p = text.c_str();
    const char* end = p + text.size();
    skipWhitespace(p, end);
    if (p >= end) return Json();
    return parseValue(p, end);
}

void Json::skipWhitespace(const char*& p, const char* end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        ++p;
}

Json Json::parseValue(const char*& p, const char* end) {
    skipWhitespace(p, end);
    if (p >= end) return Json();

    switch (*p) {
        case '{': return parseObject(p, end);
        case '[': return parseArray(p, end);
        case '"': return parseString(p, end);
        case 't':
            if (end - p >= 4 && std::memcmp(p, "true", 4) == 0) {
                p += 4;
                return Json::boolean(true);
            }
            return Json();
        case 'f':
            if (end - p >= 5 && std::memcmp(p, "false", 5) == 0) {
                p += 5;
                return Json::boolean(false);
            }
            return Json();
        case 'n':
            if (end - p >= 4 && std::memcmp(p, "null", 4) == 0) {
                p += 4;
                return Json::null();
            }
            return Json();
        default:
            return parseNumber(p, end);
    }
}

Json Json::parseObject(const char*& p, const char* end) {
    ++p; // skip '{'
    auto j = Json::object();
    skipWhitespace(p, end);
    if (p < end && *p == '}') { ++p; return j; }

    for (;;) {
        skipWhitespace(p, end);
        if (p >= end || *p != '"') return j;
        std::string key = parseRawString(p, end);
        skipWhitespace(p, end);
        if (p >= end || *p != ':') return j;
        ++p; // skip ':'
        Json val = parseValue(p, end);
        j.set(key, val);
        skipWhitespace(p, end);
        if (p >= end) return j;
        if (*p == '}') { ++p; return j; }
        if (*p == ',') { ++p; continue; }
        return j; // malformed
    }
}

Json Json::parseArray(const char*& p, const char* end) {
    ++p; // skip '['
    auto j = Json::array();
    skipWhitespace(p, end);
    if (p < end && *p == ']') { ++p; return j; }

    for (;;) {
        j.add(parseValue(p, end));
        skipWhitespace(p, end);
        if (p >= end) return j;
        if (*p == ']') { ++p; return j; }
        if (*p == ',') { ++p; continue; }
        return j; // malformed
    }
}

Json Json::parseString(const char*& p, const char* end) {
    return Json::string(parseRawString(p, end));
}

std::string Json::parseRawString(const char*& p, const char* end) {
    if (p >= end || *p != '"') return "";
    ++p; // skip opening quote
    std::string result;
    while (p < end && *p != '"') {
        if (*p == '\\') {
            ++p;
            if (p >= end) break;
            switch (*p) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'u': {
                    // \uXXXX — just consume 4 hex digits, emit as '?'
                    if (end - p > 4) p += 4;
                    result += '?';
                    break;
                }
                default: result += *p; break;
            }
        } else {
            result += *p;
        }
        ++p;
    }
    if (p < end && *p == '"') ++p; // skip closing quote
    return result;
}

Json Json::parseNumber(const char*& p, const char* end) {
    const char* start = p;
    bool isFloat = false;

    if (*p == '-') ++p;
    while (p < end && *p >= '0' && *p <= '9') ++p;
    if (p < end && *p == '.') { isFloat = true; ++p; }
    while (p < end && *p >= '0' && *p <= '9') ++p;
    if (p < end && (*p == 'e' || *p == 'E')) {
        isFloat = true;
        ++p;
        if (p < end && (*p == '+' || *p == '-')) ++p;
        while (p < end && *p >= '0' && *p <= '9') ++p;
    }

    std::string numStr(start, p);
    if (isFloat)
        return Json::number(std::strtod(numStr.c_str(), nullptr));
    return Json::number(static_cast<int64_t>(std::strtoll(numStr.c_str(), nullptr, 10)));
}

} // namespace webside
