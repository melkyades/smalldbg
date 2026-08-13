# 3.15 or newer, so CMP0091 defaults to NEW and the MSVC runtime is chosen
# through CMAKE_MSVC_RUNTIME_LIBRARY. Conan's toolchain hard-errors otherwise.
cmake_minimum_required(VERSION 3.15)
project(smalldbg VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add include directories for include and src. Note: include/smalldbg is
# deliberately NOT on the search path — on case-insensitive filesystems it would
# let smalldbg/Process.h shadow the CRT <process.h> (pulled in by <thread>),
# breaking _beginthreadex. Public headers are included as <smalldbg/...>.
include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)

# Backend selection — set to ON to use the DbgEng (WinDbg engine) backend
# instead of the plain WinAPI debug loop.  This is recommended when debugging
# x86 targets on ARM64 hosts.
if(WIN32)
    option(SMALLDBG_USE_DBGENG "Use DbgEng backend instead of plain WinAPI" ON)
else()
    option(SMALLDBG_USE_DBGENG "Use DbgEng backend instead of plain WinAPI" OFF)
endif()

# Enable debug symbols for all build types
if(MSVC)
    add_compile_options(/Zi)
    add_link_options(/DEBUG)
endif()

find_package(capstone REQUIRED)


add_library(smalldbg STATIC
    src/Arch.cpp
    src/Debugger.cpp
    src/Process.cpp
    src/Thread.cpp
    src/SymbolProvider.cpp
    src/StackTrace.cpp
    src/StackFrame.cpp
    src/LocalVariable.cpp
    src/NativeFrameProcessor.cpp
    src/bindings/CAPI.cpp
    src/Disassembler.cpp
)

target_link_libraries(smalldbg PRIVATE capstone::capstone)

# Platform-specific backend sources
if(WIN32)
    target_sources(smalldbg PRIVATE
        src/backends/WindowsBackend.cpp
        src/backends/DbgEngBackend.cpp
        src/backends/TTDBackend.cpp
    )
else()
    target_sources(smalldbg PRIVATE
        src/backends/PtraceBackend.cpp
        src/backends/PtracePlatform.cpp
        src/platform/posix/Platform.cpp
    )
    if(APPLE)
        target_sources(smalldbg PRIVATE
            src/platform/posix/macos/PtracePlatformMac.cpp
        )
    else()
        target_sources(smalldbg PRIVATE
            src/platform/posix/linux/PtracePlatformLinux.cpp
        )
    endif()
endif()

# Platform-specific symbol provider sources
if(WIN32)
    target_sources(smalldbg PRIVATE
        src/symbols/DbgHelpBackend.cpp
        src/symbols/DbgEngSymbolBackend.cpp
        src/platform/windows/HttpDownload.cpp
        src/platform/windows/Platform.cpp
    )
    target_link_libraries(smalldbg PRIVATE dbghelp dbgeng)
else()
    target_sources(smalldbg PRIVATE
        src/symbols/DwarfBackend.cpp
        src/symbols/DwarfTypes.cpp
    )
    if(APPLE)
        target_sources(smalldbg PRIVATE
            src/symbols/MachOParser.cpp
            src/platform/posix/macos/SourceResolverMac.cpp
        )
    else()
        target_sources(smalldbg PRIVATE
            src/symbols/ElfParser.cpp
            src/platform/posix/linux/SourceResolverLinux.cpp
        )
    endif()
endif()

target_include_directories(smalldbg PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include/smalldbg/ DESTINATION include/smalldbg FILES_MATCHING PATTERN "*.h")

if(SMALLDBG_USE_DBGENG)
    target_compile_definitions(smalldbg PRIVATE SMALLDBG_USE_DBGENG=1)
endif()

# enable_testing() must be called at the top level, before any subdirectory that
# registers tests (webside/tests, tests/), so `ctest` from the build root finds them.
enable_testing()

# Examples
add_subdirectory(examples)

# Tests first, so webside/tests can depend on the test_target executable.
add_subdirectory(tests)

# Webside debugger servers (Egg, Bee, etc)
add_subdirectory(webside)
