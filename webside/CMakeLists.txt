# Webside debugger servers — VM-specific frontends built on top of smalldbg
# and the shared HttpServer / WebsideServer infrastructure.

set(WEBSIDE_COMMON
    ${CMAKE_CURRENT_SOURCE_DIR}/src/HttpServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/WebsideServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Json.cpp
)

# Add every subdirectory of src/ that has its own CMakeLists.txt
file(GLOB children RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/src src/*)
foreach(child ${children})
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${child}
       AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/${child}/CMakeLists.txt)
        add_subdirectory(src/${child})
    endif()
endforeach()
