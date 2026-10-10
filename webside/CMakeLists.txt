# The Webside servers answer the Webside API about a VM, from what vmdbg reads
# of it. webside_common is what every server is built from; each dialect
# builds its own server, in a repository of its own under vms/.

find_package(httplib REQUIRED)

# What every dialect's server is built from. Servers include its headers by
# path from src/, the way they include vmdbg's from its root.
add_library(webside_common STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/HttpServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/WebsideServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/WebsideSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/MemoryListing.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Smalltalk/Session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Smalltalk/InspectorJson.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Workspace.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Smalltalk/WebsideServer.cpp
)
target_include_directories(webside_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(webside_common PUBLIC vmdbg httplib::httplib)

add_subdirectory(tests)
