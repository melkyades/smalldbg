#pragma once

#include "Smalltalk/Inspector.h"

#include <cstdint>
#include <string>

namespace webside {

/** Returns the inspector's regions as a JSON array of objects with name,
 *  start, end, size, objectMemory and code. **/
std::string regionsJson(const smalltalk::Inspector& inspector);

/** Returns one object as JSON: its class, its print string, and its first
 *  `maxSlots` slots. **/
std::string inspectObjectJson(const smalltalk::Inspector& inspector,
                              uint64_t oop, int maxSlots);

} // namespace webside
