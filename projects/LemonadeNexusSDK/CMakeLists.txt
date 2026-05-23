cmake_minimum_required(VERSION 3.25.1)
include(CreateProject)

# OpenSSL::SSL and OpenSSL::Crypto are provided by cmake/libraries/openssl.cmake
# (built from source via ExternalProject_Add — no system/Homebrew dependency).

create_project(LemonadeNexusSDK SHARED DEPENDENCIES
        nlohmann_json::nlohmann_json
        spdlog
        httplib::httplib
        sodium
        OpenSSL::SSL
        OpenSSL::Crypto
        boringtun-ffi
)

# Avoid name collision with lemonade_nexus.exe (Flutter client)
# Build as SHARED so Dart FFI can load it as a DLL
set_target_properties(LemonadeNexusSDK PROPERTIES OUTPUT_NAME "lemonade_nexus_sdk")
