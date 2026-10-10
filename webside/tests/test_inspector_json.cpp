#include <doctest/doctest.h>

#include "Json.h"
#include "Smalltalk/InspectorJson.h"
#include "Smalltalk/Session.h"
#include "ToyDialect.h"
#include "smalldbg/DisassemblyAnnotator.h"

#include <memory>
#include <string>

using smalltalk::ClassEntry;
using webside::Json;

namespace {

// An inspector over a heap of the made-up dialect, whose Point names its two
// slots.
class ToyInspector : public smalltalk::Inspector {
public:
    ToyInspector() {
        ClassEntry point;
        point.name = "Point";
        point.oop = kernel.point;
        point.instanceVariableNames = {"x", "y"};
        addClass(point);
    }

    std::unique_ptr<smalltalk::Object> objectFor(uint64_t oop) const override {
        if (oop & 1) return std::make_unique<toy::TestObject>(oop, debugger());
        return heapObjectFor(oop);
    }
    std::unique_ptr<smalltalk::HeapObject> heapObjectFor(
        uint64_t oop) const override {
        return std::make_unique<toy::TestHeapObject>(oop, debugger());
    }
    bool discoverClasses() override { return true; }

    smalldbg::Debugger* debugger() const { return kernel.heap.debugger(); }
    void objectMemory(uint64_t start, uint64_t end) {
        addRegion({"heap", start, end, vmdbg::Region::Kind::Objects, 0, ""});
    }

    mutable toy::Kernel kernel;
};

// A session over a ToyInspector whose dialect keeps a hash in each header.
class ToySession : public smalltalk::Session {
public:
    std::shared_ptr<smalldbg::Thread> vmThread() const override {
        return nullptr;
    }
    smalldbg::Debugger& debugger() const override {
        return *objects->debugger();
    }
    vmdbg::VMInspector& inspector() const override { return *objects; }

    const std::unique_ptr<ToyInspector> objects{
        std::make_unique<ToyInspector>()};

protected:
    bool onTargetOpened(const vmdbg::TargetSpec&) override { return true; }
    smalltalk::Inspector& smalltalkInspector() const override {
        return *objects;
    }
    void describeHeader(Json& json, uint64_t) const override {
        json.set("hash", 42);
    }
    bool readGreenThreads() override {
        reads++;
        return true;
    }

public:
    int reads{0};
};

std::string hex(uint64_t value) { return Json::hex(value).asString(); }

} // namespace

TEST_CASE("an object reads as its class, its value and its named slots") {
    ToyInspector inspector;
    toy::Heap& heap = inspector.kernel.heap;
    uint64_t point = heap.object(inspector.kernel.point,
                                 {toy::smallInteger(3), toy::smallInteger(4)});

    Json json = webside::inspectObjectJson(inspector, point, 0, 64);
    CHECK(json["oop"].asString() == hex(point));
    CHECK(json["class"].asString() == "Point");
    CHECK(json["size"].asInt() == 2);
    CHECK_FALSE(json["isBits"].asBool());
    CHECK_FALSE(json["immediate"].asBool());
    REQUIRE(json["slots"].size() == 2);
    CHECK(json["slots"][0]["name"].asString() == "x");
    CHECK(json["slots"][1]["name"].asString() == "y");
    CHECK(json["slots"][0]["raw"].asString() == hex(toy::smallInteger(3)));
    CHECK(json["slots"][0]["type"].asString() == "SmallInteger");
    CHECK(json["slots"][0]["value"].asString() == "3");
    CHECK(json["totalSlots"].asInt() == 2);
    CHECK_FALSE(json["truncated"].asBool());
}

TEST_CASE("slots are read from an offset, as many as asked for") {
    ToyInspector inspector;
    toy::Heap& heap = inspector.kernel.heap;
    std::vector<uint64_t> numbers;
    for (int i = 0; i < 5; i++) numbers.push_back(toy::smallInteger(i));
    uint64_t array = heap.object(inspector.kernel.array, numbers);

    Json some = webside::inspectObjectJson(inspector, array, 1, 2);
    REQUIRE(some["slots"].size() == 2);
    CHECK(some["slots"][0]["index"].asInt() == 1);
    CHECK(some["slots"][1]["value"].asString() == "2");
    CHECK(some["offset"].asInt() == 1);
    CHECK(some["totalSlots"].asInt() == 5);
    CHECK(some["truncated"].asBool());

    Json none = webside::inspectObjectJson(inspector, array, 0, 0);
    CHECK(none["slots"].size() == 0);
    CHECK(none["truncated"].asBool());
    CHECK(webside::inspectObjectJson(inspector, array, 9, 4)["slots"].size() == 0);
}

TEST_CASE("a byte object has its text instead of slots") {
    ToyInspector inspector;
    uint64_t text = inspector.kernel.heap.bytes(inspector.kernel.string, "hello");
    Json json = webside::inspectObjectJson(inspector, text, 0, 64);
    CHECK(json["isBits"].asBool());
    CHECK(json["string"].asString() == "hello");
    CHECK(json["slots"].size() == 0);
}

TEST_CASE("a listing names a word that points at an object") {
    ToySession session;
    toy::Heap& heap = session.objects->kernel.heap;
    uint64_t point = heap.object(session.objects->kernel.point,
                                 {toy::smallInteger(1), toy::smallInteger(2)});
    session.objects->objectMemory(toy::Heap::kBase, point + 0x100);

    auto source = session.annotationSource();
    CHECK(source->dataLabel(point) == "a Point");
    CHECK(source->dataLabel(0x10).empty());
}

TEST_CASE("an immediate is its value, with no header to describe") {
    ToySession session;
    Json json = Json::parse(session.describeObject(toy::smallInteger(7), 0, 64));
    CHECK(json["immediate"].asBool());
    CHECK(json["value"].asString() == "7");
    CHECK(json["size"].asInt() == 0);
    CHECK(json["hash"].isNull());
}

TEST_CASE("a dialect adds what its header says about a heap object") {
    ToySession session;
    toy::Heap& heap = session.objects->kernel.heap;
    uint64_t point = heap.object(session.objects->kernel.point,
                                 {toy::smallInteger(1), toy::smallInteger(2)});
    Json json = Json::parse(session.describeObject(point, 0, 64));
    CHECK(json["hash"].asInt() == 42);
    CHECK(json["slots"].size() == 2);
}

TEST_CASE("the processes are read once for each place the target stops") {
    ToySession session;
    session.refreshGreenThreads();
    session.refreshGreenThreads();
    CHECK(session.reads == 1);

    session.debugger().executeCommand("");   // the target may have moved
    session.refreshGreenThreads();
    CHECK(session.reads == 2);
}
