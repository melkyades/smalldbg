#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

namespace webside {

/// Lightweight JSON value — supports both building and parsing.
///
/// Building:
///   auto j = Json::object()
///       .set("name", "hello")
///       .set("count", 42)
///       .set("items", Json::array().add("a").add("b"));
///   std::string s = j.dump();
///
/// Parsing:
///   auto j = Json::parse(body);
///   std::string name = j["name"].asString();
///   int count = j["count"].asInt();
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

    /// Produce a JSON string like "0x0012abcd" (hex with 0x prefix).
    static Json hex(uint32_t v);
    /// Produce a hex string for 64-bit values.
    static Json hex(uint64_t v);

    // ---- parsing ----
    /// Parse a JSON string into a Json value.  Returns null on error.
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
    /// Look up a field by key (object).  Returns null Json if missing.
    const Json& operator[](const std::string& key) const;
    /// Look up an element by index (array).  Returns null Json if out of range.
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

    /// Escape a raw string for safe embedding in a JSON value.
    static std::string escape(const std::string& s);

private:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };
    Type type;
    bool boolVal{false};
    int64_t intVal{0};
    double doubleVal{0.0};
    std::string strVal;
    std::vector<Json> items;                          // Array
    std::vector<std::pair<std::string, Json>> fields;  // Object (insertion order)

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

} // namespace webside
