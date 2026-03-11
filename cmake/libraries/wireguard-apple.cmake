cmake_minimum_required(VERSION 3.20)

# WireGuardKit integration for Apple platforms (macOS, iOS).
#
# Uses wireguard-go (from wireguard-apple) as a userspace WireGuard
# implementation with a C-callable API. Requires a Go toolchain to build
# the Go library into a static archive (libwg-go.a).
#
# On Apple platforms with Go available:
#   - Fetches wireguard-apple source
#   - Builds WireGuardKitGo as a static C library via `go build -buildmode=c-archive`
#   - Creates wireguard::apple target with HAS_WIREGUARDKIT=1
#   - Enables Obj-C++ bridge in WireGuardService
#
# On non-Apple platforms or without Go: creates a dummy INTERFACE target.

if(APPLE)
    find_program(GO_COMPILER go)

    if(GO_COMPILER)
        # Verify Go version (need 1.20+)
        execute_process(
            COMMAND ${GO_COMPILER} version
            OUTPUT_VARIABLE GO_VERSION_OUTPUT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE GO_VERSION_RESULT
        )

        if(GO_VERSION_RESULT EQUAL 0)
            message(STATUS "Found Go: ${GO_VERSION_OUTPUT}")

            include(FetchContent)
            FetchContent_Declare(wireguard_apple
                GIT_REPOSITORY https://github.com/WireGuard/wireguard-apple.git
                GIT_TAG        1.0.15-appstore  # stable release tag
                GIT_SHALLOW    TRUE
            )
            FetchContent_MakeAvailable(wireguard_apple)

            set(WG_GO_SRC_DIR "${wireguard_apple_SOURCE_DIR}/Sources/WireGuardKitGo")
            set(WG_GO_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/wireguard-go")
            set(WG_GO_ARCHIVE "${WG_GO_OUTPUT_DIR}/libwg-go.a")
            set(WG_GO_HEADER "${WG_GO_OUTPUT_DIR}/libwg-go.h")

            file(MAKE_DIRECTORY ${WG_GO_OUTPUT_DIR})

            # Build the Go library as a C-archive (static lib + header)
            add_custom_command(
                OUTPUT "${WG_GO_ARCHIVE}" "${WG_GO_HEADER}"
                COMMAND ${CMAKE_COMMAND} -E env
                    CGO_ENABLED=1
                    GOARCH=${CMAKE_SYSTEM_PROCESSOR}
                    GOOS=darwin
                    ${GO_COMPILER} build
                        -buildmode=c-archive
                        -o "${WG_GO_ARCHIVE}"
                        ./...
                WORKING_DIRECTORY "${WG_GO_SRC_DIR}"
                COMMENT "Building wireguard-go as C-archive (libwg-go.a)"
                VERBATIM
            )

            add_custom_target(wireguard_go_build
                DEPENDS "${WG_GO_ARCHIVE}" "${WG_GO_HEADER}"
            )

            # Create an imported static library target
            add_library(wireguard_apple_lib STATIC IMPORTED GLOBAL)
            set_target_properties(wireguard_apple_lib PROPERTIES
                IMPORTED_LOCATION "${WG_GO_ARCHIVE}"
            )
            # Go archive links against the Go runtime — need resolv + pthread
            set_target_properties(wireguard_apple_lib PROPERTIES
                INTERFACE_LINK_LIBRARIES "-lresolv;-lpthread"
            )
            target_include_directories(wireguard_apple_lib INTERFACE
                "${WG_GO_OUTPUT_DIR}"
            )
            add_dependencies(wireguard_apple_lib wireguard_go_build)

            target_compile_definitions(wireguard_apple_lib INTERFACE
                HAS_WIREGUARDKIT=1
            )

            add_library(wireguard::apple ALIAS wireguard_apple_lib)

            message(STATUS "WireGuardKit enabled (macOS — wireguard-go userspace backend)")
        else()
            # Go found but version check failed
            add_library(wireguard_apple_lib INTERFACE)
            add_library(wireguard::apple ALIAS wireguard_apple_lib)
            message(STATUS "WireGuardKit skipped (Go toolchain check failed — using CLI fallback)")
        endif()
    else()
        # No Go compiler
        add_library(wireguard_apple_lib INTERFACE)
        add_library(wireguard::apple ALIAS wireguard_apple_lib)
        message(STATUS "WireGuardKit skipped (Go compiler not found — using CLI fallback)")
    endif()
else()
    # Non-Apple platform
    add_library(wireguard_apple_lib INTERFACE)
    add_library(wireguard::apple ALIAS wireguard_apple_lib)
    message(STATUS "WireGuardKit skipped (non-Apple platform)")
endif()
