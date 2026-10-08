#include "InspectorJson.h"

#include "Json.h"
#include "Smalltalk/HeapObject.h"
#include "Smalltalk/Object.h"

#include <algorithm>

namespace webside {

std::string regionsJson(const smalltalk::Inspector& inspector) {
    auto array = Json::array();
    for (const vmdbg::Region& region : inspector.regions()) {
        array.add(Json::object()
            .set("name", region.name)
            .set("start", Json::hex(region.start))
            .set("end", Json::hex(region.end))
            .set("size", static_cast<int64_t>(region.size()))
            .set("objectMemory", region.isObjectMemory)
            .set("code", region.isCode));
    }
    return array.dump();
}

std::string retainersJson(smalltalk::Inspector& inspector, uint64_t oop) {
    auto array = Json::array();
    for (const auto& step : inspector.retainersOf(oop)) {
        auto entry = Json::object()
            .set("oop", Json::hex(step.oop))
            .set("class", step.className)
            .set("isClass", step.isClass);
        if (!step.detail.empty()) entry.set("detail", step.detail);
        array.add(std::move(entry));
    }
    return array.dump();
}

std::string inspectObjectJson(const smalltalk::Inspector& inspector,
                              uint64_t oop, int maxSlots) {
    auto object = inspector.objectFor(oop);
    if (!object || !object->isValid())
        return Json::object().set("error", "unreadable oop").dump();

    auto result = Json::object()
        .set("oop", Json::hex(oop))
        .set("class", object->className())
        .set("printString", object->printString());

    if (object->isImmediate()) {
        result.set("immediate", true);
        return result.dump();
    }

    auto heap = inspector.heapObjectFor(oop);
    if (!heap || !heap->isValid()) return result.dump();

    result.set("size", static_cast<int64_t>(heap->size()));
    result.set("bytes", heap->isBytes());

    if (heap->isBytes()) {
        result.set("value", heap->bytesAsString());
        return result.dump();
    }

    auto slots = Json::array();
    int shown = std::min<int>(static_cast<int>(heap->size()),
                              std::max(maxSlots, 0));
    for (int i = 0; i < shown; i++) {
        auto slot = heap->slotObjectAt(i);
        auto entry = Json::object()
            .set("index", i)
            .set("oop", Json::hex(heap->rawSlotAt(i)));
        if (slot) entry.set("printString", slot->printString());
        slots.add(std::move(entry));
    }
    result.set("slots", slots);
    return result.dump();
}

} // namespace webside
