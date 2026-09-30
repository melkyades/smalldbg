# Webside debugger servers — VM-specific frontends built on top of smalldbg
# and the shared HttpServer / WebsideServer infrastructure.

find_package(httplib REQUIRED)

# The VM code lives in vmdbg now; it is compiled in here until vmdbg is a
# library of its own.
set(VMDBG_SRC ${CMAKE_SOURCE_DIR}/vmdbg/src)

set(WEBSIDE_COMMON
    ${CMAKE_CURRENT_SOURCE_DIR}/src/HttpServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/WebsideServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/WebsideSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Json.cpp
    ${VMDBG_SRC}/VMSession.cpp
    ${VMDBG_SRC}/MemoryTypeMap.cpp
)
set(WEBSIDE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/src ${VMDBG_SRC})

# Add every subdirectory of src/ that has its own CMakeLists.txt
file(GLOB children RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/src src/*)
foreach(child ${children})
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${child}
       AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/${child}/CMakeLists.txt)
        add_subdirectory(src/${child})
    endif()
endforeach()

add_subdirectory(tests)
