#include <doctest/doctest.h>

#include "Json.h"

using vmdbg::Json;

TEST_CASE("a document dumps and parses back to the same values") {
    Json document = Json::object()
        .set("name", "point")
        .set("count", 3)
        .set("ok", true)
        .set("none", nullptr)
        .set("items", Json::array().add("a").add(2));

    Json read = Json::parse(document.dump());
    CHECK(read["name"].asString() == "point");
    CHECK(read["count"].asInt() == 3);
    CHECK(read["ok"].asBool());
    CHECK(read["none"].isNull());
    REQUIRE(read["items"].size() == 2);
    CHECK(read["items"][0].asString() == "a");
    CHECK(read["items"][1].asInt() == 2);
}

TEST_CASE("text is escaped so that it reads back unchanged") {
    std::string text = "quote \" backslash \\ newline \n tab \t";
    CHECK(Json::parse(Json::string(text).dump()).asString() == text);
}

TEST_CASE("a control character is written as a unicode escape") {
    std::string text = "name";
    text += '\0';
    text += '\x1b';
    CHECK(Json::string(text).dump() == "\"name\\u0000\\u001b\"");
}

TEST_CASE("an address is written as hex and reads back as a number") {
    Json address = Json::hex(uint64_t(0x7ff012345678));
    CHECK(address.asString().rfind("0x", 0) == 0);
    CHECK(std::stoull(address.asString(), nullptr, 16) == 0x7ff012345678ULL);
}

TEST_CASE("a missing key or bad text reads as null") {
    CHECK(Json::object()["absent"].isNull());
    CHECK(Json::parse("{not json").isNull());
}
