#include <doctest/doctest.h>

#include "Json.h"
#include "Smalltalk/InspectorJson.h"
#include "Smalltalk/FrameUnwinder.h"
#include "Smalltalk/Session.h"
#include "ToyHeap.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/StackTrace.h"

#include <map>
#include <memory>

using smalltalk::ClassEntry;
using smalltalk::MethodEntry;
using webside::Json;

namespace {

// An inspector whose classes and regions are whatever the test adds.
class TestInspector : public smalltalk::Inspector {
public:
    std::unique_ptr<smalltalk::Object> objectFor(uint64_t) const override {
        return nullptr;
    }
    std::unique_ptr<smalltalk::HeapObject> heapObjectFor(
        uint64_t) const override {
        return nullptr;
    }
    bool discoverClasses() override { return true; }
    std::vector<MethodEntry> methodsOf(
        const std::string& className) const override {
        auto found = methods.find(className);
        return found == methods.end() ? std::vector<MethodEntry>()
                                      : found->second;
    }
    std::string sourceOf(const MethodEntry& method) const override {
        auto found = sources.find(method.oop);
        return found == sources.end() ? std::string() : found->second;
    }
    // Point>>x pushes x and returns it; nothing else decodes.
    std::vector<smalltalk::Bytecode> bytecodesOf(const MethodEntry& method) const override {
        if (method.oop != 0x300) return {};
        return {{1, {0x10}, "push x", std::nullopt}, {2, {0x7C}, "return", std::nullopt}};
    }

    void add(ClassEntry entry) { addClass(std::move(entry)); }
    void add(const MethodEntry& method, const std::string& source = {}) {
        methods[method.className].push_back(method);
        if (!source.empty()) sources[method.oop] = source;
    }
    void add(vmdbg::Region region) { addRegion(std::move(region)); }

    // The heap retainersOf traces; none unless a test lays one out.
    std::unique_ptr<ToyHeap> heap;

protected:
    std::map<std::string, std::vector<MethodEntry>> methods;
    std::map<uint64_t, std::string> sources;

    std::unique_ptr<vmdbg::Tracer> makeTracer() override {
        return std::move(heap);
    }
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

MethodEntry methodEntry(const std::string& className,
                        const std::string& selector,
                        const std::string& category, uint64_t oop) {
    MethodEntry method;
    method.className = className;
    method.selector = selector;
    method.category = category;
    method.oop = oop;
    return method;
}

// A session over a TestInspector with Object <- Collection <- (Array, Bag)
// and Object <- Point, a few methods on each side of Point and one on
// Object, and nothing opened.
class TestSession : public smalltalk::Session {
public:
    TestSession() {
        ClassEntry point = classEntry("Point", 0x30, "Object", 0x10);
        point.category = "Kernel-Numbers";
        point.instanceVariableNames = {"x", "y"};
        point.classVariableNames = {"Origin"};
        ClassEntry collection = classEntry("Collection", 0x20, "Object", 0x10);
        collection.instanceVariableNames = {"tally"};
        classes->add(classEntry("Object", 0x10, "", 0));
        classes->add(collection);
        classes->add(point);
        classes->add(classEntry("Bag", 0x40, "Collection", 0x20));
        classes->add(classEntry("Array", 0x50, "Collection", 0x20));
        classes->add(classEntry("Point class", 0x31, "Object class", 0x11));

        classes->add(methodEntry("Point", "x", "accessing", 0x300),
                     "x\r\t^x");
        classes->add(methodEntry("Point", "y", "accessing", 0x310));
        classes->add(methodEntry("Point", "printOn:", "printing", 0x320));
        classes->add(methodEntry("Point class", "x:y:", "instance creation",
                                 0x330));
        classes->add(methodEntry("Object", "isNil", "testing", 0x340));
    }

    std::shared_ptr<smalldbg::Thread> vmThread() const override {
        return nullptr;
    }
    smalldbg::Debugger& debugger() const override { return *dbg; }
    vmdbg::VMInspector& inspector() const override { return *classes; }

    // Promoted so the tests can reach them.
    using smalltalk::Session::classDefinition;
    using smalltalk::Session::isMetaclassName;
    using smalltalk::Session::buildFrameDetailJson;
    using smalltalk::Session::buildFrameArgumentsJson;

    // Each green thread has one frame, running Point class>>x:y:.
    std::vector<std::unique_ptr<smalldbg::StackFrame>>
    readGreenFrames(int) const override {
        ++greenReads;
        auto frame = std::make_unique<smalldbg::StackFrame>();
        auto running = std::make_unique<smalltalk::FrameMetadata>();
        running->className = "Point class";
        running->selector = "x:y:";
        frame->metadata = std::move(running);
        std::vector<std::unique_ptr<smalldbg::StackFrame>> frames;
        frames.push_back(std::move(frame));
        return frames;
    }
    mutable int greenReads{0};

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

TEST_CASE("a metaclass the class table lacks is made from its class") {
    TestSession session;
    Json meta = Json::parse(session.getClass("Bag class"));
    CHECK(meta["name"].asString() == "Bag class");
    CHECK(meta["class"].asString() == "Metaclass");
    CHECK(meta["superclass"].asString() == "Collection class");
    CHECK(Json::parse(session.getClass("Object class"))["superclass"]
              .asString() == "Class");
    CHECK(session.getClass("Missing class") == "{}");
}

TEST_CASE("a class list keeps to the classes under its root") {
    TestSession session;
    CHECK(session.listClasses("Collection", true, false, -1) ==
          "[\"Array\",\"Bag\",\"Collection\"]");
    Json all = Json::parse(session.listClasses("Collection", false, false, -1));
    CHECK(namesIn(all) ==
          std::vector<std::string>{"Array", "Bag", "Collection"});
    CHECK(all[2]["oop"].asString() == Json::hex(uint64_t(0x20)).asString());
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
    CHECK(variables[2]["value"].isNull());
    CHECK(namesIn(Json::parse(session.getInstanceVariables("Point"))) ==
          std::vector<std::string>{"x", "y"});
    CHECK(namesIn(Json::parse(session.getClassVariables("Point"))) ==
          std::vector<std::string>{"Origin"});
}

TEST_CASE("a class's variables include the inherited ones, defined where") {
    TestSession session;
    Json variables = Json::parse(session.getVariables("Bag"));
    REQUIRE(variables.size() == 1);
    CHECK(variables[0]["name"].asString() == "tally");
    CHECK(variables[0]["class"].asString() == "Collection");
    CHECK(session.getInstanceVariables("Bag") == "[]");
}

TEST_CASE("a class's categories are those of its methods") {
    TestSession session;
    CHECK(session.getCategories("Point") ==
          "[\"accessing\",\"printing\"]");
    CHECK(session.getCategories("Bag") == "[]");
    CHECK(session.getUsedCategories("Point") ==
          "[\"accessing\",\"printing\",\"testing\"]");
}

TEST_CASE("a method reads with its source, or its heading when it has none") {
    TestSession session;
    CHECK(session.getSelectors("Point") == "[\"x\",\"y\",\"printOn:\"]");

    Json x = Json::parse(session.getMethod("Point", "x"));
    CHECK(x["methodClass"].asString() == "Point");
    CHECK(x["category"].asString() == "accessing");
    CHECK(x["source"].asString() == "x\r\t^x");
    CHECK(x["hasSource"].asBool());
    CHECK(x["oop"].asString() == Json::hex(uint64_t(0x300)).asString());

    Json y = Json::parse(session.getMethod("Point", "y"));
    CHECK(y["source"].asString() == "Point>>y");
    CHECK_FALSE(y["hasSource"].asBool());
    CHECK(session.getMethod("Point", "z") == "{}");

    CHECK(Json::parse(session.getMethods("Point")).size() == 3);
    Json classSide = Json::parse(session.getMethods("Point class"));
    REQUIRE(classSide.size() == 1);
    CHECK(classSide[0]["selector"].asString() == "x:y:");
}

TEST_CASE("a search finds classes, then selectors from both sides, once each") {
    TestSession session;
    CHECK(session.search("o", true, "including", "class") ==
          "[{\"type\":\"class\",\"text\":\"Collection\"},"
          "{\"type\":\"class\",\"text\":\"Object\"},"
          "{\"type\":\"class\",\"text\":\"Point\"}]");
    Json selectors = Json::parse(session.search("x", false, "beginning",
                                                "selector"));
    REQUIRE(selectors.size() == 2);
    CHECK(selectors[0]["text"].asString() == "x");
    CHECK(selectors[1]["text"].asString() == "x:y:");
    CHECK(session.search("ON:", true, "ending", "")
          == "[{\"type\":\"selector\",\"text\":\"printOn:\"}]");
    CHECK(session.search("", true, "including", "all") == "[]");
}

TEST_CASE("a session with nothing attached says it is detached") {
    TestSession session;
    CHECK_FALSE(session.isActive());
    CHECK_FALSE(session.getPid().has_value());
    CHECK(session.getStopReason() == "detached");
}

TEST_CASE("retainers read as oop, class, whether a class, and detail") {
    TestInspector inspector;
    inspector.add(classEntry("Holder", 0x10100, "Object", 0x10));
    inspector.heap = std::make_unique<ToyHeap>();
    inspector.heap->space("old", 0x10000, 0x1000);
    inspector.heap->object(0x10000, {0x10100});
    inspector.heap->object(0x10100, {0x10200});
    inspector.heap->object(0x10200, {});
    inspector.heap->roots = {0x10000};

    Json chain = Json::parse(webside::retainersJson(inspector, 0x10200));
    REQUIRE(chain.size() == 2);
    CHECK(chain[0]["oop"].asString() == Json::hex(uint64_t(0x10100)).asString());
    CHECK(chain[0]["isClass"].asBool());
    CHECK(chain[0]["detail"].asString() == "Holder");
    CHECK_FALSE(chain[1]["isClass"].asBool());
    CHECK(webside::retainersJson(inspector, 0x10200) == "[]");
}

TEST_CASE("a method's bytecodes come decoded, with their bytes in hex") {
    TestSession session;
    Json answer = Json::parse(session.getMethodBytecodes("Point", "x"));
    CHECK(answer["selector"].asString() == "x");
    REQUIRE(answer["bytecodes"].size() == 2);
    CHECK(answer["bytecodes"][0]["pc"].asInt() == 1);
    CHECK(answer["bytecodes"][0]["bytes"].asString() == "10");
    CHECK(answer["bytecodes"][1]["text"].asString() == "return");

    CHECK(session.getMethodBytecodes("Point", "y") == "{}");
    CHECK(session.getMethodBytecodes("Point", "z") == "{}");
}

TEST_CASE("a Smalltalk frame shows its method's class and source") {
    TestSession session;
    smalldbg::StackFrame frame;
    auto running = std::make_unique<smalltalk::FrameMetadata>();
    running->className = "Point";
    running->selector = "x";
    frame.metadata = std::move(running);

    Json detail = Json::parse(session.buildFrameDetailJson(frame, 1));
    CHECK(detail["class"]["name"].asString() == "Point");
    CHECK(detail["method"]["source"].asString() == "x\r\t^x");
    CHECK(detail["hasSource"].asBool());

    auto block = std::make_unique<smalltalk::FrameMetadata>();
    block->className = "Point";
    block->selector = "x";
    block->isBlock = true;
    block->blockIndex = 1;
    frame.metadata = std::move(block);
    detail = Json::parse(session.buildFrameDetailJson(frame, 1));
    CHECK(detail["method"]["selector"].asString() == "x [block 1]");
}

TEST_CASE("a green thread's frames are read once until its processes are") {
    TestSession session;
    smalldbg::StackTrace* stack = session.greenStack(0);
    REQUIRE(stack != nullptr);
    CHECK(stack->getFrameCount() == 1);
    CHECK(session.greenStack(0) == stack);
    CHECK(session.greenReads == 1);
    session.greenStack(1);
    CHECK(session.greenReads == 2);
}

TEST_CASE("a frame's arguments are named by its selector's keywords") {
    TestSession session;
    smalldbg::StackFrame frame;
    auto running = std::make_unique<smalltalk::FrameMetadata>();
    running->selector = "x:y:";
    running->arguments = {0x10, 0x20};
    frame.metadata = std::move(running);

    Json arguments = Json::parse(session.buildFrameArgumentsJson(frame));
    REQUIRE(arguments.size() == 2);
    CHECK(arguments[0]["name"].asString() == "x");
    CHECK(arguments[1]["name"].asString() == "y");

    auto block = std::make_unique<smalltalk::FrameMetadata>();
    block->selector = "x:y:";
    block->isBlock = true;
    block->arguments = {0x10};
    frame.metadata = std::move(block);
    arguments = Json::parse(session.buildFrameArgumentsJson(frame));
    REQUIRE(arguments.size() == 1);
    CHECK(arguments[0]["name"].asString() == "arg1");
}
