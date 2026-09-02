cmake_minimum_required(VERSION 3.25.1)
include(CreateProject)

# Generated version header (values computed in cmake/version.cmake)
configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/include/LemonadeNexus/Core/Version.hpp.in"
        "${CMAKE_CURRENT_BINARY_DIR}/include/LemonadeNexus/Core/Version.hpp"
        @ONLY
)

# OpenSSL::SSL and OpenSSL::Crypto are provided by cmake/libraries/openssl.cmake
# tss2::fapi provided by cmake/libraries/tss2-fapi.cmake
# (built from source via ExternalProject_Add — no system/Homebrew dependency).

create_project(LemonadeNexus DEPENDENCIES
        asio::asio
        nlohmann_json::nlohmann_json
        spdlog
        jwt-cpp
        magic_enum
        xxhash
        httplib::httplib
        sodium
        OpenSSL::SSL
        OpenSSL::Crypto
        tss2::fapi
        c-ares::cares
        sqlite3
        boringtun-ffi
        virtual-netstack
)

target_compile_definitions(LemonadeNexus PUBLIC
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
)

target_compile_definitions(LemonadeNexusApp PUBLIC
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
)

if(WIN32)
    target_link_libraries(LemonadeNexus PRIVATE ws2_32 mswsock iphlpapi urlmon wintrust shell32)
    target_link_libraries(LemonadeNexusApp PRIVATE ws2_32 mswsock iphlpapi urlmon wintrust shell32)
endif()

# ── Install targets ──────────────────────────────────────────────────────────

# Rename binary from LemonadeNexusApp → lemonade-nexus
set_target_properties(LemonadeNexusApp PROPERTIES OUTPUT_NAME "lemonade-nexus")

# Binary
install(TARGETS LemonadeNexusApp
        RUNTIME DESTINATION bin
        COMPONENT Runtime)

# License and third-party attribution notices ship with every package
install(FILES "${CMAKE_SOURCE_DIR}/LICENSE"
              "${CMAKE_SOURCE_DIR}/THIRD_PARTY_NOTICES.md"
        DESTINATION share/doc/lemonade-nexus
        COMPONENT Runtime)

# Platform-specific service files
if(UNIX AND NOT APPLE)
    # Linux: systemd unit
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/systemd/lemonade-nexus.service"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
elseif(APPLE)
    # macOS: launchd plist
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/macos/io.lemonade-nexus.plist"
            DESTINATION Library/LaunchDaemons
            COMPONENT Runtime)
endif()
