# vmreport writes a readable account of a dump or a trace to a file: why the
# target stopped, what was loaded, what the virtual machine was doing, and what
# each thread was doing. The file can be handed to someone who does not run a
# debugger. Each dialect builds its own report program on this library, which
# leaves it only the VM's section to write.

if(NOT WIN32)
    return()
endif()

add_library(vmreport STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/Report.cpp)
target_include_directories(vmreport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(vmreport PUBLIC vmdbg)

add_subdirectory(tests)
