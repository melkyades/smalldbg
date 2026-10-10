# vmdbg -- reading a virtual machine's own world.
#
# What a VM keeps and how it keeps it: objects, classes, frames, the heap and
# the processes running on it. Nothing here serves anything or knows that it is
# being asked over HTTP, so a state reporter or a front end for another
# language reads a VM through this without taking Webside with it.
#
# It sits on smalldbg for the process, the memory and the symbols, and adds the
# layer above: what those bytes mean to the runtime that wrote them.

set(VMDBG_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Target.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/VMSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Json.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Setup.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/VMInspector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/AddressTable.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Tracer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/MemoryTypeMap.cpp
)

# The Smalltalk layer. Dialects build on it from repositories of their own.
add_subdirectory(src/Smalltalk)

add_library(vmdbg STATIC ${VMDBG_SOURCES} ${SMALLTALK_SOURCES})

target_include_directories(vmdbg PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vmdbg PUBLIC smalldbg)

add_subdirectory(tests)
