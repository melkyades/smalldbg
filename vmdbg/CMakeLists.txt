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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/VMSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/VMInspector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/MemoryTypeMap.cpp
)

# The Smalltalk layer, and the dialects that bring their own CMakeLists.txt.
# A dialect is picked up by being present, so one that lives in a repository of
# its own appears when it is checked out and is simply absent when it is not.
add_subdirectory(src/Smalltalk)

add_library(vmdbg STATIC ${VMDBG_SOURCES} ${SMALLTALK_SOURCES})

target_include_directories(vmdbg PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vmdbg PUBLIC smalldbg)

add_subdirectory(tests)
