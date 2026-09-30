#include "EggInspectorJson.h"
#include "Json.h"
#include "EggInspector.h"

#include <algorithm>

// Egg is a 64-bit interpreter; a stack slot is one pointer.
static constexpr int PTR_SIZE = 8;

namespace webside {

static Json slotToJson(int index, const egg::EggObject& slotObj) {
    auto slot = Json::object();
    slot.set("index", index);
    slot.set("raw", Json::hex(slotObj.oop()));

    if (slotObj.isSmallInteger()) {
        auto smi = slotObj.asSmallInteger();
        slot.set("type", "SmallInteger");
        slot.set("class", "SmallInteger");
        slot.set("value", smi.value());
    } else if (slotObj.isHeapObject()) {
        auto slotHeap = slotObj.asHeapObject();
        slot.set("type", "object");
        slot.set("class", slotHeap.className());
        slot.set("value", slotHeap.printString());
    } else {
        slot.set("type", "nil");
        slot.set("class", "UndefinedObject");
        slot.set("value", "nil");
    }
    return slot;
}

std::string inspectEggObject(const egg::EggInspector& inspector, uint64_t oop, int maxSlots) {
    maxSlots = std::clamp(maxSlots, 0, 1024);

    auto obj = inspector.objectAt(oop);
    auto result = Json::object();
    result.set("oop", Json::hex(oop));

    if (obj.isSmallInteger()) {
        auto smi = obj.asSmallInteger();
        result.set("class", "SmallInteger");
        result.set("size", 0);
        result.set("hash", 0);
        result.set("flags", "0x00");
        result.set("isBits", false);
        result.set("isIndexed", false);
        result.set("isNamed", false);
        result.set("isExtended", false);
        result.set("value", smi.value());
        result.set("string", std::to_string(smi.value()));
        result.set("slots", Json::array());
        result.set("totalSlots", 0);
        result.set("truncated", false);
    } else if (obj.isHeapObject()) {
        auto heap = obj.asHeapObject();
        uint32_t totalSlots = heap.size();

        result.set("class", heap.className());
        result.set("size", static_cast<int64_t>(totalSlots));
        result.set("hash", static_cast<int64_t>(heap.hash()));
        result.set("flags", Json::hex(static_cast<uint32_t>(heap.flags())));
        result.set("isBits", heap.isBytes());
        result.set("isIndexed", heap.isArrayed());
        result.set("isNamed", heap.isNamed());
        result.set("isExtended", !heap.isSmallHeader());

        if (heap.isBytes()) {
            result.set("string", heap.bytesAsString());
            result.set("value", heap.printString());
        } else {
            result.set("string", nullptr);
            result.set("value", heap.printString());
        }

        int readCount = std::min(static_cast<int>(totalSlots), maxSlots);
        auto slotsArr = Json::array();
        for (int i = 0; i < readCount; i++)
            slotsArr.add(slotToJson(i, heap.objectSlotAt(i)));

        result.set("slots", slotsArr);
        result.set("totalSlots", static_cast<int64_t>(totalSlots));
        result.set("truncated", readCount < static_cast<int>(totalSlots));
    } else {
        result.set("class", "UndefinedObject");
        result.set("size", 0);
        result.set("hash", 0);
        result.set("flags", "0x00");
        result.set("isBits", false);
        result.set("isIndexed", false);
        result.set("isNamed", false);
        result.set("isExtended", false);
        result.set("value", nullptr);
        result.set("string", "nil");
        result.set("slots", Json::array());
        result.set("totalSlots", 0);
        result.set("truncated", false);
    }

    return result.dump();
}

std::string eggStackContentsJson(const egg::EggInspector& inspector, const egg::EggInspector::EvaluatorState& st) {
    if (!st.valid || st.stackBase == 0 || st.stackSize == 0)
        return "[]";

    // Used slots run from regSP (top, inclusive) down to the stack bottom.
    uint64_t from = st.regSP;
    uint64_t to   = st.stackSize;
    if (from > to) return "[]";

    auto arr = webside::Json::array();
    for (uint64_t i = from; i <= to; i++) {
        uint64_t raw = inspector.readStackSlot(st, i);
        arr.add(webside::Json::object()
            .set("index",   static_cast<int64_t>(i))
            .set("address", webside::Json::hex(st.stackBase + (i - 1) * PTR_SIZE))
            .set("oop",     webside::Json::hex(raw))
            .set("desc",    inspector.describeRemoteObject(inspector.objectAt(raw)))
            .set("isBP",    i == st.regBP)
            .set("isSP",    i == st.regSP));
    }
    return arr.dump();
}

} // namespace webside
