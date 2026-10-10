#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

namespace vmdbg {

/** A Json is a JSON value. It is built with the factories and set or add,
 *  written with dump, and read back with parse and the accessors. **/
class Json {
public:
    Json();  // null

    // ---- factories ----
    static Json object();
    static Json array();
    static Json string(const std::string& s);
    static Json number(int n);
    static Json number(int64_t n);
    static Json number(uint32_t n);
    static Json number(double d);
    static Json boolean(bool b);
    static Json null();

    /** Returns `v` as a string of eight hex digits after "0x". **/
    static Json hex(uint32_t v);
    /** Returns `v` as a string of sixteen hex digits after "0x". **/
    static Json hex(uint64_t v);

    // ---- parsing ----
    /** Returns the value `text` holds, or null when it does not hold exactly
     *  one complete JSON value. **/
    static Json parse(const std::string& text);

    // ---- object mutators ----
    Json& set(const std::string& key, const Json& val);
    Json& set(const std::string& key, const std::string& val);
    Json& set(const std::string& key, const char* val);
    Json& set(const std::string& key, int val);
    Json& set(const std::string& key, int64_t val);
    Json& set(const std::string& key, uint32_t val);
    Json& set(const std::string& key, bool val);
    Json& set(const std::string& key, std::nullptr_t);

    // ---- array mutators ----
    Json& add(const Json& val);
    Json& add(const std::string& val);
    Json& add(const char* val);
    Json& add(int val);
    Json& add(int64_t val);
    Json& add(bool val);

    // ---- accessors (for parsed values) ----
    /** Returns an object's field named `key`, or null when it has none. **/
    const Json& operator[](const std::string& key) const;
    /** Returns an array's element at `index`, or null when there is none. **/
    const Json& operator[](size_t index) const;

    std::string asString() const;
    int64_t asInt() const;
    uint64_t asUInt() const;
    double asNumber() const;
    bool asBool() const;

    bool isNull() const;
    bool isObject() const;
    bool isArray() const;
    bool isString() const;
    bool isNumber() const;
    bool isBool() const;

    // ---- queries ----
    bool empty() const;
    size_t size() const;

    // ---- iteration ----
    const std::vector<Json>& elements() const;
    const std::vector<std::pair<std::string, Json>>& entries() const;

    // ---- serialization ----
    std::string dump() const;

    /** Returns `s` with the characters JSON cannot hold raw escaped. **/
    static std::string escape(const std::string& s);

private:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };
    Type type;
    bool boolVal{false};
    int64_t intVal{0};
    double doubleVal{0.0};
    std::string strVal;
    std::vector<Json> items;                          // Array
    // Object fields, in the order they were set.
    std::vector<std::pair<std::string, Json>> fields;

    void appendTo(std::string& out) const;
    static void appendEscaped(std::string& out, const std::string& s);

    // ---- parser internals ----
    static Json parseValue(const char*& p, const char* end);
    static Json parseObject(const char*& p, const char* end);
    static Json parseArray(const char*& p, const char* end);
    static Json parseString(const char*& p, const char* end);
    static Json parseNumber(const char*& p, const char* end);
    static void skipWhitespace(const char*& p, const char* end);
    static std::string parseRawString(const char*& p, const char* end);
};

} // namespace vmdbg
