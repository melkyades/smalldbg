# What every Smalltalk dialect shares: an object model, an inspector, a session
# and the frame walking. A dialect adds only what its own VM does differently,
# from a repository of its own under vms/.

# The object model reads through a debugger, which may be one built over an
# image file: a heap need not belong to a running process.
set(SMALLTALK_MODEL
    ${CMAKE_CURRENT_SOURCE_DIR}/Object.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HeapObject.cpp
)

set(SMALLTALK_COMMON
    ${SMALLTALK_MODEL}
    ${CMAKE_CURRENT_SOURCE_DIR}/ObjectNamer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Inspector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/MethodParser.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SyntaxTree.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FrameUnwinder.cpp
)

set(SMALLTALK_SOURCES ${SMALLTALK_COMMON} PARENT_SCOPE)
