cmake_minimum_required(VERSION 3.20)
project(VeylCore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT so the DLL runs on machines without the VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# A 32-bit configure (cmake -A Win32, done by build.ps1 into native\build32) builds only the
# sandbox monitor for 32-bit programs, plus a 32-bit probe for the sandbox tests.
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_library(Veyl.SandboxHook32 SHARED sandbox/hook.cpp)
    target_compile_definitions(Veyl.SandboxHook32 PRIVATE UNICODE _UNICODE)
    target_compile_options(Veyl.SandboxHook32 PRIVATE /W4 /permissive- /utf-8 /EHsc)

    add_executable(Veyl.SandboxProbe32 tests/sandbox_probe.cpp)
    target_compile_definitions(Veyl.SandboxProbe32 PRIVATE UNICODE _UNICODE)
    target_link_libraries(Veyl.SandboxProbe32 PRIVATE ws2_32)
    return()
endif()

add_library(Veyl.Core SHARED
    src/util.cpp
    src/crypto.cpp
    src/vault.cpp
    src/clipboard.cpp
    src/scanner.cpp
    src/signatures.cpp
    src/quarantine.cpp
    src/sandbox.cpp
)
target_include_directories(Veyl.Core PUBLIC include)
target_compile_definitions(Veyl.Core PRIVATE VEYL_CORE_EXPORTS UNICODE _UNICODE)
target_compile_options(Veyl.Core PRIVATE /W4 /permissive- /guard:cf /sdl /utf-8)
target_link_options(Veyl.Core PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT /CETCOMPAT)
target_link_libraries(Veyl.Core PRIVATE bcrypt rpcrt4 amsi wintrust user32)

add_executable(Veyl.Core.Tests tests/core_tests.cpp)
target_compile_definitions(Veyl.Core.Tests PRIVATE UNICODE _UNICODE VEYL_FIXTURES=L"${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
target_compile_options(Veyl.Core.Tests PRIVATE /W4 /utf-8)
target_link_libraries(Veyl.Core.Tests PRIVATE Veyl.Core)

# Sandbox monitor, injected into sandboxed programs. Built without /guard:cf on purpose:
# it calls through runtime-generated syscall trampolines that CFG would reject.
add_library(Veyl.SandboxHook SHARED sandbox/hook.cpp)
target_compile_definitions(Veyl.SandboxHook PRIVATE UNICODE _UNICODE)
target_compile_options(Veyl.SandboxHook PRIVATE /W4 /permissive- /utf-8 /EHsc)

# Windows 11 main right-click menu handler. Packaged into Veyl.Menu.msix by build.ps1.
add_library(Veyl.ShellMenu SHARED shellmenu/menu.cpp shellmenu/menu.def)
target_compile_definitions(Veyl.ShellMenu PRIVATE UNICODE _UNICODE)
target_compile_options(Veyl.ShellMenu PRIVATE /W4 /permissive- /guard:cf /sdl /utf-8 /EHsc)
target_link_options(Veyl.ShellMenu PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT /CETCOMPAT)

add_executable(Veyl.SandboxProbe tests/sandbox_probe.cpp)
target_compile_definitions(Veyl.SandboxProbe PRIVATE UNICODE _UNICODE)
target_link_libraries(Veyl.SandboxProbe PRIVATE ws2_32)

add_executable(Veyl.Sandbox.Tests tests/sandbox_tests.cpp)
target_compile_definitions(Veyl.Sandbox.Tests PRIVATE UNICODE _UNICODE)
target_compile_options(Veyl.Sandbox.Tests PRIVATE /W4 /utf-8)
target_link_libraries(Veyl.Sandbox.Tests PRIVATE Veyl.Core)
add_dependencies(Veyl.Sandbox.Tests Veyl.SandboxHook Veyl.SandboxProbe)
