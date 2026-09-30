# Egg Smalltalk debugger
set(EGG_VM ${VMDBG_SRC}/Smalltalk/Egg)

add_executable(webside_egg
    main.cpp
    EggWebsideServer.cpp
    EggInspectorJson.cpp
    ${EGG_VM}/EggDebugSession.cpp
    ${EGG_VM}/EggInspector.cpp
    ${EGG_VM}/EggHeapObject.cpp
    ${EGG_VM}/EggKnownObjects.cpp
    ${WEBSIDE_COMMON}
)
target_include_directories(webside_egg PRIVATE
    ${WEBSIDE_INCLUDES} ${EGG_VM} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(webside_egg PRIVATE smalldbg httplib::httplib)

add_executable(egg_crash_test ${EGG_VM}/egg_crash_test.cpp)
target_link_libraries(egg_crash_test PRIVATE smalldbg)

# Sign with debugger entitlement so task_for_pid works without sudo (macOS only)
if(APPLE)
    set(ENTITLEMENTS_FILE "${CMAKE_SOURCE_DIR}/debugger.entitlements")
    foreach(tgt webside_egg egg_crash_test)
        add_custom_command(TARGET ${tgt} POST_BUILD
            COMMAND codesign --force --sign - --entitlements ${ENTITLEMENTS_FILE} $<TARGET_FILE:${tgt}>
            COMMENT "Signing ${tgt} with debugger entitlement"
        )
    endforeach()
endif()
