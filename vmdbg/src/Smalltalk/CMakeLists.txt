# What every Smalltalk dialect shares, and the dialects. Each dialect brings a
# sources.cmake naming its VM code, so one that is not checked out is simply
# absent.

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
    ${CMAKE_CURRENT_SOURCE_DIR}/FrameUnwinder.cpp
)

set(DIALECT_SOURCES "")
file(GLOB children RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*)
foreach(child ${children})
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${child}
       AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${child}/sources.cmake)
        include(${CMAKE_CURRENT_SOURCE_DIR}/${child}/sources.cmake)
    endif()
endforeach()

set(SMALLTALK_SOURCES ${SMALLTALK_COMMON} ${DIALECT_SOURCES} PARENT_SCOPE)
