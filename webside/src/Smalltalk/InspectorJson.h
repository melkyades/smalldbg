#pragma once

#include "Json.h"
#include "Smalltalk/Inspector.h"

#include <cstdint>
#include <string>

namespace webside {

using vmdbg::Json;

/** Returns the chain that keeps `oop` alive as a JSON array of objects with
 *  oop, class, isClass and detail. **/
std::string retainersJson(smalltalk::Inspector& inspector, uint64_t oop);

/** Returns one object as JSON: its class, its print string, its size, and up
 *  to `maxSlots` of its slots from `firstSlot`, each named when its class
 *  names it. A byte object has its bytes as text instead of slots. **/
Json inspectObjectJson(const smalltalk::Inspector& inspector, uint64_t oop,
                       int firstSlot, int maxSlots);

} // namespace webside
