#include <doctest/doctest.h>

#include "Json.h"
#include "Smalltalk/InspectorJson.h"
#include "Smalltalk/Session.h"
#include "smalldbg/Debugger.h"

#include <memory>

using smalltalk::ClassEntry;
using webside::Json;

namespace {

// An inspector whose classes and regions are whatever the test adds.
class TestInspector : public smalltalk::Inspector {
public:
    StackRegion evaluatorStack() const override { return {}; }
    std::unique_ptr<smalltalk::Object> objectFor(uint64_t) const override {
        return nullptr;
    }
    std::unique_ptr<smalltalk::HeapObject> heapObjectFor(
        uint64_t) const override {
        return nullptr;
    }
    bool discoverClasses() override { return true; }

    void add(ClassEntry entry) { addClass(std::move(entry)); }
    void add(vmdbg::Region region) { addRegion(std::move(region)); }
};

ClassEntry classEntry(const std::string& name, uint64_t oop,
                      const std::string& superclassName, uint64_t superclass) {
    ClassEntry entry;
    entry.name = name;
    entry.oop = oop;
    entry.superclassName = superclassName;
    entry.superclass = superclass;
    return entry;
}

// A session over a TestInspector with Object <- Collection <- (Array, Bag)
// and Object <- Point, and nothing opened.
class TestSession : public smalltalk::Session {
public:
    TestSession() {
        ClassEntry point = classEntry("Point", 0x30, "Object", 0x10);
        point.category = "Kernel-Numbers";
        point.instanceVariableNames = {"x", "y"};
        point.classVariableNames = {"Origin"};
        classes->add(classEntry("Object", 0x10, "", 0));
        classes->add(classEntry("Collection", 0x20, "Object", 0x10));
        classes->add(point);
        classes->add(classEntry("Bag", 0x40, "Collection", 0x20));
        classes->add(classEntry("Array", 0x50, "Collection", 0x20));
        classes->add(classEntry("Point class", 0x31, "Object class", 0x11));
    }

    std::string getRegisters() const override { return "{}"; }
    std::string getSelectors(const std::string&) const override { return "[]"; }
    std::string getMethods(const std::string&) const override { return "[]"; }
    std::string getMethod(const std::string&,
                          const std::string&) const override {
        return "{}";
    }
    std::string search(const std::string&, bool, const std::string&,
                       const std::string&) const override { return "[]"; }
    std::string listBreakpoints() const override { return "[]"; }
    std::string readMemory(uint64_t, size_t) const override { return "{}"; }
    std::string waitForEvent(int) override { return "{}"; }
    std::string describeObject(uint64_t, size_t) const override { return "{}"; }
    std::shared_ptr<smalldbg::Thread> vmThread() const override {
        return nullptr;
    }
    smalldbg::Debugger& debugger() const override { return *dbg; }
    vmdbg::VMInspector& inspector() const override { return *classes; }

    // Promoted so the tests can reach them.
    using smalltalk::Session::classDefinition;
    using smalltalk::Session::isMetaclassName;

protected:
    bool onTargetOpened(const vmdbg::TargetSpec&) override { return true; }
    smalltalk::Inspector& smalltalkInspector() const override {
        return *classes;
    }

private:
    const std::unique_ptr<smalldbg::Debugger> dbg{
        std::make_unique<smalldbg::Debugger>(smalldbg::Mode::External)};
    const std::unique_ptr<TestInspector> classes{
        std::make_unique<TestInspector>()};
};

std::vector<std::string> namesIn(const Json& array) {
    std::vector<std::string> names;
    for (const Json& element : array.elements())
        names.push_back(element["name"].asString());
    return names;
}

} // namespace

TEST_CASE("a class reads as the Webside client expects it") {
    TestSession session;
    Json point = Json::parse(session.getClass("Point"));
    CHECK(point["name"].asString() == "Point");
    CHECK(point["class"].asString() == "Point class");
    CHECK(point["superclass"].asString() == "Object");
    CHECK(point["category"].asString() == "Kernel-Numbers");
    CHECK(point["definition"].asString() ==
          "Object subclass: #Point\r\tinstanceVariableNames: 'x y'"
          "\r\tcategory: 'Kernel-Numbers'");

    CHECK(Json::parse(session.getClass("Object"))["superclass"].isNull());
    CHECK(session.getClass("Missing") == "{}");
}

TEST_CASE("a metaclass is a Metaclass and is defined by its name") {
    TestSession session;
    CHECK(TestSession::isMetaclassName("Point class"));
    CHECK_FALSE(TestSession::isMetaclassName("Point"));
    CHECK_FALSE(TestSession::isMetaclassName(" class"));

    Json meta = Json::parse(session.getClass("Point class"));
    CHECK(meta["class"].asString() == "Metaclass");
    CHECK(meta["definition"].asString() == "Point class");
}

TEST_CASE("a class list keeps to the classes under its root") {
    TestSession session;
    Json all = Json::parse(session.listClasses("Collection", true, false, -1));
    CHECK(namesIn(all) ==
          std::vector<std::string>{"Array", "Bag", "Collection"});
    CHECK(all[0].entries().size() == 1);
}

TEST_CASE("a class tree starts at the root and stops at the depth asked") {
    TestSession session;
    Json whole = Json::parse(session.listClasses("", true, true, -1));
    REQUIRE(whole.size() == 1);
    CHECK(whole[0]["name"].asString() == "Object");
    Json below = whole[0]["subclasses"];
    CHECK(namesIn(below) == std::vector<std::string>{"Collection", "Point"});
    CHECK(namesIn(below[0]["subclasses"]) ==
          std::vector<std::string>{"Array", "Bag"});

    Json shallow = Json::parse(session.listClasses("", true, true, 1));
    CHECK(shallow[0]["subclasses"].size() == 2);
    CHECK(shallow[0]["subclasses"][0]["subclasses"].isNull());
}

TEST_CASE("a class's neighbours and variables come from the class table") {
    TestSession session;
    CHECK(namesIn(Json::parse(session.getSubclasses("Collection"))) ==
          std::vector<std::string>{"Array", "Bag"});
    CHECK(namesIn(Json::parse(session.getSuperclasses("Bag"))) ==
          std::vector<std::string>{"Collection", "Object"});

    Json variables = Json::parse(session.getVariables("Point"));
    CHECK(namesIn(variables) == std::vector<std::string>{"x", "y", "Origin"});
    CHECK(variables[2]["type"].asString() == "class");
    CHECK(namesIn(Json::parse(session.getInstanceVariables("Point"))) ==
          std::vector<std::string>{"x", "y"});
    CHECK(namesIn(Json::parse(session.getClassVariables("Point"))) ==
          std::vector<std::string>{"Origin"});
    CHECK(session.getCategories("Point") == "[\"Kernel-Numbers\"]");
    CHECK(session.getCategories("Object") == "[]");
}

TEST_CASE("a session with nothing attached says it is detached") {
    TestSession session;
    CHECK_FALSE(session.isActive());
    CHECK_FALSE(session.getPid().has_value());
    CHECK(session.getStopReason() == "detached");
}

TEST_CASE("regions read as name, bounds, size and kind") {
    TestInspector inspector;
    inspector.add(vmdbg::Region{"old", 0x1000, 0x3000, true, false});
    inspector.add(vmdbg::Region{"code", 0x8000, 0x8100, false, true});

    Json regions = Json::parse(webside::regionsJson(inspector));
    REQUIRE(regions.size() == 2);
    CHECK(regions[0]["name"].asString() == "old");
    CHECK(regions[0]["start"].asString() ==
          Json::hex(uint64_t(0x1000)).asString());
    CHECK(regions[0]["size"].asInt() == 0x2000);
    CHECK(regions[0]["objectMemory"].asBool());
    CHECK(regions[1]["code"].asBool());
}
