cmake_minimum_required(VERSION 3.25.1)
include(CreateProject)

find_package(OpenSSL REQUIRED)

create_project(LemonadeNexusSDK DEPENDENCIES
        nlohmann_json::nlohmann_json
        spdlog
        httplib::httplib
        sodium
        OpenSSL::SSL
        OpenSSL::Crypto
)
