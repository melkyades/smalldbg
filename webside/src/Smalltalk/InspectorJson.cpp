#include "InspectorJson.h"

#include "Json.h"
#include "Smalltalk/HeapObject.h"
#include "Smalltalk/Object.h"

#include <algorithm>
#include <vector>

namespace webside {

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

namespace {

Json hexOf(uint64_t value, const smalltalk::Object& object) {
    return object.slotSize() <= 4 ? Json::hex(static_cast<uint32_t>(value))
                                  : Json::hex(value);
}

const char* kindOf(const smalltalk::Object& object) {
    if (object.isSmallInteger()) return "SmallInteger";
    if (object.isNil()) return "nil";
    if (object.isImmediate()) return "immediate";
    return object.isHeapObject() ? "object" : "invalid";
}

Json slotJson(const smalltalk::HeapObject& heap, int index,
              const std::vector<std::string>& names) {
    auto json = Json::object()
        .set("index", index)
        .set("raw", hexOf(heap.rawSlotAt(index), heap));
    if (index < static_cast<int>(names.size())) json.set("name", names[index]);
    if (auto slot = heap.slotObjectAt(index)) {
        json.set("type", kindOf(*slot))
            .set("class", slot->className())
            .set("value", slot->printString());
    }
    return json;
}

} // namespace

Json inspectObjectJson(const smalltalk::Inspector& inspector, uint64_t oop,
                       int firstSlot, int maxSlots) {
    auto object = inspector.objectFor(oop);
    if (!object || !object->isValid())
        return Json::object().set("error", "unreadable oop");

    auto json = Json::object()
        .set("oop", hexOf(oop, *object))
        .set("class", object->className())
        .set("value", object->printString())
        .set("immediate", object->isImmediate());

    auto heap = object->isImmediate() ? nullptr : inspector.heapObjectFor(oop);
    const int total = heap && heap->isValid() && !heap->isBytes()
        ? static_cast<int>(heap->size()) : 0;
    json.set("size", static_cast<int64_t>(heap ? heap->size() : 0));
    json.set("isBits", heap && heap->isBytes());
    if (heap && heap->isBytes()) json.set("string", heap->bytesAsString());

    const int first = std::clamp(firstSlot, 0, total);
    const int shown = std::min(total - first, std::max(maxSlots, 0));
    const auto names = inspector.slotNamesOf(object->className());
    auto slots = Json::array();
    for (int i = first; i < first + shown; i++)
        slots.add(slotJson(*heap, i, names));
    json.set("slots", slots);
    if (first != 0) json.set("offset", first);
    json.set("totalSlots", total);
    json.set("truncated", first + shown < total);
    return json;
}

} // namespace webside
