cmake_minimum_required(VERSION 3.25.1)

# nexus-updater: verifies, stages, and installs releases in place (design
# docs/Design-Auto-Update.md, Phase 4). It runs as root from a systemd timer
# and holds no server keys. It reuses the server library for release-approval
# verification, so the updater and the server apply the same rules.

# POSIX only: the updater forks commands, swaps files with rename(2), and
# talks to the server over a unix socket.
if(WIN32)
    return()
endif()

# The logic lives in a library so the cycle is testable with fake GitHub
# responses, a fake server socket, and a temporary root
# (tests/test_nexus_updater.cpp).
add_library(LemonadeNexusUpdaterCore
        src/FileSwap.cpp
        src/HealthGate.cpp
        src/OsPackages.cpp
        src/ReleaseTag.cpp
        src/ReleaseVerifier.cpp
        src/SigstoreVerifier.cpp
        src/Transport.cpp
        src/Updater.cpp)

target_compile_features(LemonadeNexusUpdaterCore PUBLIC cxx_std_20)
target_include_directories(LemonadeNexusUpdaterCore PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(LemonadeNexusUpdaterCore PUBLIC
        LemonadeNexus
        httplib::httplib
        nlohmann_json::nlohmann_json
        OpenSSL::Crypto
        sodium
        spdlog)
target_compile_definitions(LemonadeNexusUpdaterCore PUBLIC ASIO_STANDALONE ASIO_NO_DEPRECATED)

add_executable(nexus-updater src/main.cpp)
target_compile_features(nexus-updater PRIVATE cxx_std_20)
target_link_libraries(nexus-updater PRIVATE LemonadeNexusUpdaterCore)

if(NOT MSVC AND TARGET all_projects)
    add_dependencies(all_projects nexus-updater)
endif()

if(UNIX AND NOT APPLE)
    install(TARGETS nexus-updater
            RUNTIME DESTINATION bin
            COMPONENT Runtime)
    install(FILES "${CMAKE_SOURCE_DIR}/release/sigstore-trusted-root.json"
            DESTINATION lib/lemonade-nexus/updater
            COMPONENT Runtime)
    install(FILES
            "${CMAKE_SOURCE_DIR}/packaging/systemd/nexus-updater.service"
            "${CMAKE_SOURCE_DIR}/packaging/systemd/nexus-updater.timer"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
endif()
