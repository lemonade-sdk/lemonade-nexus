cmake_minimum_required(VERSION 3.20)

# Embeddable WireGuard C library from wireguard-tools.
# Linux-only: uses netlink sockets for kernel WireGuard communication.
# On non-Linux platforms, this creates a dummy INTERFACE target so the build
# still works but HAS_EMBEDDABLE_WG is not defined (CLI fallback is used).

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(FetchContent)
    FetchContent_Declare(wireguard_embeddable
        GIT_REPOSITORY https://github.com/WireGuard/wireguard-tools.git
        GIT_TAG        v1.0.20210914  # stable release
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(wireguard_embeddable)

    # Build the embeddable library as a static C library
    set(WG_EMBED_DIR "${wireguard_embeddable_SOURCE_DIR}/contrib/embeddable-wg-library")

    add_library(wireguard_embeddable_lib STATIC
        "${WG_EMBED_DIR}/wireguard.c"
    )
    target_include_directories(wireguard_embeddable_lib PUBLIC
        "${WG_EMBED_DIR}"
    )
    # It's a C library, needs C compiler
    set_target_properties(wireguard_embeddable_lib PROPERTIES
        LINKER_LANGUAGE C
        C_STANDARD 11
    )
    target_compile_definitions(wireguard_embeddable_lib PUBLIC
        HAS_EMBEDDABLE_WG=1
    )
    # Alias for consistency
    add_library(wireguard::embeddable ALIAS wireguard_embeddable_lib)

    message(STATUS "Embeddable WireGuard library enabled (Linux netlink API)")
else()
    # Non-Linux: provide a header-only dummy target
    add_library(wireguard_embeddable_lib INTERFACE)
    add_library(wireguard::embeddable ALIAS wireguard_embeddable_lib)
    message(STATUS "Embeddable WireGuard library skipped (non-Linux platform — using CLI fallback)")
endif()
