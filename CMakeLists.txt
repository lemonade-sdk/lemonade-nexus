cmake_minimum_required(VERSION 3.25.1)
project(Lemonade_Nexus LANGUAGES C CXX)

#-----------------------------------------------------------------------------
# Project-wide Settings
#-----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set build-type specific compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os -DNDEBUG")

# Enable ccache for faster rebuilds if available
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_FOUND})
    message(STATUS "Using ccache for faster compilation.")
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

#-----------------------------------------------------------------------------
# Libraries
#-----------------------------------------------------------------------------
include(libraries/openssl)        # Must come before httplib and jwt-cpp (they depend on OpenSSL)
include(libraries/asio)
include(libraries/nlohmann_json)
include(libraries/spdlog)
include(libraries/jwt-cpp)
include(libraries/magic_enum)
include(libraries/xxHash)
include(libraries/httplib)
include(libraries/libsodium)
include(libraries/wireguard-embeddable)
include(libraries/wireguard-apple)
include(libraries/wireguard-nt)
include(libraries/c-ares)
include(libraries/sqlite3)

#-----------------------------------------------------------------------------
# Projects
#-----------------------------------------------------------------------------
add_subdirectory(projects/LemonadeNexus)
add_subdirectory(projects/LemonadeNexusSDK)

#-----------------------------------------------------------------------------
# Tests (optional, enabled by default)
#-----------------------------------------------------------------------------
option(BUILD_TESTING "Build unit and integration tests" ON)
if(BUILD_TESTING)
    include(libraries/googletest)
    enable_testing()
    add_subdirectory(tests)
endif()

#-----------------------------------------------------------------------------
# Packaging (CPack)
#-----------------------------------------------------------------------------
include(packaging)
