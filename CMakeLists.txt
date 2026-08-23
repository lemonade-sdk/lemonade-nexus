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

include(libraries/tss2-fapi)      # TPM2 Feature API (Linux only; no-op elsewhere)
include(libraries/openssl)        # Must come before httplib and jwt-cpp (they depend on OpenSSL)
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

#-----------------------------------------------------------------------------
# Projects
#-----------------------------------------------------------------------------
add_subdirectory(projects/LemonadeNexus)
add_subdirectory(projects/LemonadeNexusSDK)
add_subdirectory(projects/LemonadeNexusSidecar)

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
