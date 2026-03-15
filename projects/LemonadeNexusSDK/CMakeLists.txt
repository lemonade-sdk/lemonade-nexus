cmake_minimum_required(VERSION 3.25.1)
include(CreateProject)

# OpenSSL::SSL and OpenSSL::Crypto are provided by cmake/libraries/openssl.cmake
# (built from source via ExternalProject_Add — no system/Homebrew dependency).

create_project(LemonadeNexusSDK DEPENDENCIES
        nlohmann_json::nlohmann_json
        spdlog
        httplib::httplib
        sodium
        OpenSSL::SSL
        OpenSSL::Crypto
        boringtun-ffi
)
