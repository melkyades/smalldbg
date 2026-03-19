# Egg Smalltalk debugger (macOS ARM64)
if(NOT APPLE)
    return()
endif()

add_executable(webside_egg
    main.cpp
    EggWebsideServer.cpp
    EggDebugSession.cpp
    EggInspector.cpp
    EggHeapObject.cpp
    EggKnownObjects.cpp
    ${WEBSIDE_COMMON}
)
target_link_libraries(webside_egg PRIVATE smalldbg)

add_executable(egg_crash_test egg_crash_test.cpp)
target_link_libraries(egg_crash_test PRIVATE smalldbg)

# Sign with debugger entitlement so task_for_pid works without sudo
set(ENTITLEMENTS_FILE "${CMAKE_SOURCE_DIR}/debugger.entitlements")
foreach(tgt webside_egg egg_crash_test)
    add_custom_command(TARGET ${tgt} POST_BUILD
        COMMAND codesign --force --sign - --entitlements ${ENTITLEMENTS_FILE} $<TARGET_FILE:${tgt}>
        COMMENT "Signing ${tgt} with debugger entitlement"
    )
endforeach()
