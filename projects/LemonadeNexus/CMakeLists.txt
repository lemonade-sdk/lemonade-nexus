cmake_minimum_required(VERSION 3.25.1)
include(CreateProject)

find_package(OpenSSL REQUIRED)

create_project(LemonadeNexus DEPENDENCIES
        asio::asio
        nlohmann_json::nlohmann_json
        spdlog
        jwt-cpp
        magic_enum
        xxhash
        httplib::httplib
        sodium
        wireguard::embeddable
        wireguard::apple
        wireguard::nt
        OpenSSL::SSL
        OpenSSL::Crypto
        c-ares::cares
        sqlite3
)

target_compile_definitions(LemonadeNexus PUBLIC
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
)

target_compile_definitions(LemonadeNexusApp PUBLIC
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
)

# ── Install targets ──────────────────────────────────────────────────────────

# Rename binary from LemonadeNexusApp → lemonade-nexus
set_target_properties(LemonadeNexusApp PROPERTIES OUTPUT_NAME "lemonade-nexus")

# Binary
install(TARGETS LemonadeNexusApp
        RUNTIME DESTINATION bin
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
