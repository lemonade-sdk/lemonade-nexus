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
        frost-ffi
        storage-threshold
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

# Build-time generator for the unsigned release-approval bundle. Not installed;
# the separately authorized signing ceremony consumes its output.
add_executable(nexus-release-bundle tools/release_bundle_main.cpp)
target_link_libraries(nexus-release-bundle PRIVATE LemonadeNexus)

# The release guard: verifies a rollout proof from Tier 1 finalized state
# (docs/Releasing.md). Not installed; release.yml runs it before it publishes.
add_executable(nexus-rollout-check tools/rollout_check_main.cpp)
target_link_libraries(nexus-rollout-check PRIVATE LemonadeNexus)

# Tree merge ceremony tooling (design A9): export, merge, finalize. Not
# installed; the operator runs it during the one-time ceremony. No key
# material is read or written.
add_executable(nexus-tree-merge tools/tree_merge_main.cpp)
target_link_libraries(nexus-tree-merge PRIVATE LemonadeNexus)

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
    # The bootstrap step between installing and starting: it writes the config
    # the unit runs on, so it ships with the unit rather than beside it.
    install(PROGRAMS "${CMAKE_SOURCE_DIR}/scripts/nexus-bootstrap"
            DESTINATION bin
            COMPONENT Runtime)
    # The one-time tree merge, run by the operator on the root server
    # (docs/Tree-Merge-Ceremony.md). It holds no key; the server does the
    # signing through its root-only control socket.
    install(PROGRAMS "${CMAKE_SOURCE_DIR}/scripts/nexus-tree-migrate"
            DESTINATION bin
            COMPONENT Runtime)
    # Verifier-owned release policy: generated after the final tree and ELF
    # hashes are known, so it is an external package input, not a tracked file.
    # Runtime accepts it only after Genesis delegation and release-authority
    # signatures verify; replacing it cannot change the executable digest.
    set(LEMONADE_RELEASE_APPROVAL_FILE
        "${CMAKE_SOURCE_DIR}/packaging/release/release-approval.UNSIGNED.example.json"
        CACHE FILEPATH "Externally generated signed release-approval v1 object")
    if(NOT EXISTS "${LEMONADE_RELEASE_APPROVAL_FILE}")
        message(FATAL_ERROR
            "LEMONADE_RELEASE_APPROVAL_FILE does not exist: ${LEMONADE_RELEASE_APPROVAL_FILE}")
    endif()
    install(FILES "${LEMONADE_RELEASE_APPROVAL_FILE}"
            RENAME release-approval.json
            DESTINATION lib/lemonade-nexus/release
            COMPONENT Runtime)
    # Public DNS port -> unprivileged dns_port. Both files are inert on install:
    # the unit has ConditionPathExists on a conf that only
    # `nexus-bootstrap --install-dns-nat` writes, so installing the package
    # never changes the host's firewall state.
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/systemd/nexus-dns-nat.service"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/nftables/nexus-dns-nat.nft"
            DESTINATION lib/lemonade-nexus
            COMPONENT Runtime)
elseif(APPLE)
    # macOS: launchd plist
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/macos/io.lemonade-nexus.plist"
            DESTINATION Library/LaunchDaemons
            COMPONENT Runtime)
endif()
