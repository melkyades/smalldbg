#pragma once

#include <smalldbg/Debugger.h>

#include <cstdint>
#include <functional>
#include <string>

namespace smalltalk {

/**
 * A name for an oop that the object's own class cannot supply.
 *
 * Printing asks an object what it is, and the answer comes from its class. For
 * the structures a VM keeps beside a class -- its dictionary array, its
 * dictionaries -- that answer is "an Array of MethodDictionaries", which says
 * nothing about whose they are. A dialect that can tell registers one here, and
 * from then on every print of that oop uses it, at the top level and nested
 * inside another object alike.
 *
 * Naming happens while a person waits, so a namer must answer from what it
 * already knows rather than reading the target.
 **/
using ObjectNamer = std::function<std::string(uint64_t)>;

/** Let `namer` name the oops read through `debugger`. **/
void setObjectNamer(smalldbg::Debugger* debugger, ObjectNamer namer);

/** The name for `oop`, or empty when no namer has one. **/
std::string objectName(smalldbg::Debugger* debugger, uint64_t oop);

} // namespace smalltalk
