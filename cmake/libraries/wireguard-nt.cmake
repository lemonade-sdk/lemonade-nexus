cmake_minimum_required(VERSION 3.20)

# WireGuard-NT integration for Windows.
#
# Uses the wireguard-nt kernel driver via dynamic loading (LoadLibrary).
# Only the header file (wireguard.h) is needed at compile time — the DLL
# is loaded at runtime from the application directory or system32.
#
# On Windows:
#   - Fetches wireguard-nt source for the API header
#   - Creates wireguard::nt target with HAS_WIREGUARD_NT=1
#   - At runtime, wireguard.dll must be shipped alongside the executable
#     (download from https://download.wireguard.com/wireguard-nt/)
#
# On non-Windows platforms: creates a dummy INTERFACE target.

if(WIN32)
    include(FetchContent)
    FetchContent_Declare(wireguard_nt
        GIT_REPOSITORY https://git.zx2c4.com/wireguard-nt
        GIT_TAG        0.10.1
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(wireguard_nt)

    # Header-only — no library to link at build time (dynamic loading at runtime)
    add_library(wireguard_nt_lib INTERFACE)
    target_include_directories(wireguard_nt_lib INTERFACE
        "${wireguard_nt_SOURCE_DIR}/api"
    )
    target_compile_definitions(wireguard_nt_lib INTERFACE
        HAS_WIREGUARD_NT=1
    )
    add_library(wireguard::nt ALIAS wireguard_nt_lib)

    message(STATUS "WireGuard-NT enabled (Windows — kernel driver via wireguard.dll)")
else()
    # Non-Windows: provide a dummy target
    add_library(wireguard_nt_lib INTERFACE)
    add_library(wireguard::nt ALIAS wireguard_nt_lib)
    message(STATUS "WireGuard-NT skipped (non-Windows platform)")
endif()
