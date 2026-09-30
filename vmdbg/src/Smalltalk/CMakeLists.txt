# The Smalltalk dialects. Each brings a sources.cmake naming its VM code, so a
# dialect that is not checked out is simply absent.

set(DIALECT_SOURCES "")
file(GLOB children RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*)
foreach(child ${children})
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${child}
       AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${child}/sources.cmake)
        include(${CMAKE_CURRENT_SOURCE_DIR}/${child}/sources.cmake)
    endif()
endforeach()

set(SMALLTALK_SOURCES ${DIALECT_SOURCES} PARENT_SCOPE)
