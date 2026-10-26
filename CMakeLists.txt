cmake_minimum_required(VERSION 3.25.1)

# Static runtime on Windows to avoid a VC++ redistributable dependency.
if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" LEMONADE_NEXUS_VERSION LIMIT_COUNT 1)

project(Lemonade_Nexus VERSION ${LEMONADE_NEXUS_VERSION} LANGUAGES C CXX)

#-----------------------------------------------------------------------------
# Project-wide Settings
#-----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build everything position-independent so static dependencies (spdlog, sodium,
# …) can be linked into the shared FFI library liblemonade_nexus_sdk.so. Without
# this, GNU ld rejects the .so link ("recompile with -fPIC"); harmless for the
# server/test executables. Set before the library includes below so fetched
# deps inherit it.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Static dependencies. The attestation profile pins the hash of every shared
# library the server and nexus-attestd load (release/fleet-profile.json), so
# each shared library that ships outside a Nexus release is a way for an OS
# update to break attestation. With this option, configure accepts only the
# pinned OpenSSL and links it statically (cmake/libraries/openssl.cmake), and
# Linux executables also link libstdc++ and libgcc statically. glibc (libc,
# libm, ld-linux) stays dynamic. Shared libraries such as the SDK keep the C++
# runtime of their host process.
option(LEMONADE_NEXUS_STATIC_DEPS
       "Link the pinned OpenSSL, and on Linux libstdc++ and libgcc, statically"
       ${PROJECT_IS_TOP_LEVEL})
if(LEMONADE_NEXUS_STATIC_DEPS AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
        AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    include(CheckLinkerFlag)
    check_linker_flag(CXX "-static-libstdc++;-static-libgcc" LEMONADE_NEXUS_HAVE_STATIC_CXX_RUNTIME)
    if(NOT LEMONADE_NEXUS_HAVE_STATIC_CXX_RUNTIME)
        message(FATAL_ERROR
            "LEMONADE_NEXUS_STATIC_DEPS=ON, but the toolchain cannot link libstdc++ "
            "statically. Install the static libstdc++ package, or configure with "
            "-DLEMONADE_NEXUS_STATIC_DEPS=OFF.")
    endif()
    set(LEMONADE_NEXUS_STATIC_CXX_RUNTIME ON)
    add_link_options(
        "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-static-libstdc++;-static-libgcc>")
endif()

# GNU-style flags only; MSVC would discard its own /O2 defaults for these.
if(NOT MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG "-g")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os -DNDEBUG")
endif()

# Enable ccache for faster rebuilds if available
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_FOUND})
    message(STATUS "Using ccache for faster compilation.")
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(version)

#-----------------------------------------------------------------------------
# Libraries
#-----------------------------------------------------------------------------
# Let fetched deps declaring cmake_minimum_required(<3.5) configure on CMake 4+
if(CMAKE_VERSION VERSION_GREATER_EQUAL 4.0 AND NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM)
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
endif()

# Also drops the tss2 transitive deps (json-c, libcurl, libuuid) for the
# sidecar/embeddable profiles.
option(LEMONADE_NEXUS_MINIMAL_DEPS "Build without TPM FAPI support" OFF)

# The client SDK alone, for the mobile builds (scripts/build-sdk-mobile.sh):
# only the SDK's own dependencies, no server, sidecar, tools or tests, so the
# build cross-compiles for iOS and Android.
option(LEMONADE_NEXUS_SDK_ONLY "Build only the client SDK and its dependencies" OFF)

if(LEMONADE_NEXUS_SDK_ONLY)
    include(libraries/openssl)
    include(libraries/nlohmann_json)
    include(libraries/spdlog)
    include(libraries/httplib)
    include(libraries/libsodium)
    include(libraries/boringtun)
    include(libraries/virtual-netstack)
    add_subdirectory(projects/LemonadeNexusSDK)
    return()
endif()

include(libraries/openssl)        # Must come before tss2-fapi, httplib, and jwt-cpp (they depend on OpenSSL)
include(libraries/tss2-fapi)      # TPM2 Feature API (Linux only; no-op elsewhere)
include(libraries/asio)
include(libraries/nlohmann_json)
include(libraries/spdlog)
include(libraries/jwt-cpp)
include(libraries/magic_enum)
include(libraries/xxHash)
include(libraries/httplib)
include(libraries/libsodium)
include(libraries/c-ares)
include(libraries/sqlite3)
include(libraries/boringtun)
include(libraries/virtual-netstack)
include(libraries/frost)
include(libraries/storage-threshold)

#-----------------------------------------------------------------------------
# Projects
#-----------------------------------------------------------------------------
add_subdirectory(projects/LemonadeNexus)
add_subdirectory(projects/LemonadeNexusSDK)
add_subdirectory(projects/LemonadeNexusSidecar)
add_subdirectory(projects/LemonadeNexusAttestd)
add_subdirectory(projects/LemonadeNexusUpdater)

#-----------------------------------------------------------------------------
# Tests (optional, enabled by default)
#-----------------------------------------------------------------------------
# Off by default when embedded in a parent project.
option(BUILD_TESTING "Build unit and integration tests" ${PROJECT_IS_TOP_LEVEL})
if(BUILD_TESTING)
    include(libraries/googletest)
    enable_testing()
    add_subdirectory(tests)
endif()

#-----------------------------------------------------------------------------
# Packaging (CPack)
#-----------------------------------------------------------------------------
if(PROJECT_IS_TOP_LEVEL)
    include(packaging)
endif()
