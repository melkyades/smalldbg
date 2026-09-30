# Egg's VM code, added to the vmdbg library.
list(APPEND DIALECT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/Egg/EggHeapObject.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Egg/EggInspector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Egg/EggKnownObjects.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Egg/EggObject.cpp
)
