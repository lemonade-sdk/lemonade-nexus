cmake_minimum_required(VERSION 3.25.1)

# The evidence-producing daemon: one AttestationChallenge in, one hardware-backed
# AttestationEvidence out. It is the only component on the host trusted with the
# TPM and the root-only IMA log; see systemd/nexus-attestd.service.

# The logic lives in a library so the refusal gate and the codec are testable
# without starting a daemon or owning a TPM (tests/test_nexus_attestd.cpp).
add_library(LemonadeNexusAttestdCore
        src/AttestdGate.cpp
        src/AttestdFraming.cpp
        src/AttestdCodec.cpp
        src/AttestdClient.cpp
        src/AttestdService.cpp
        src/AttestdSocket.cpp)

target_compile_features(LemonadeNexusAttestdCore PUBLIC cxx_std_20)
target_include_directories(LemonadeNexusAttestdCore PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
# LemonadeNexus carries the attestation types, the evidence chain and libsodium.
target_link_libraries(LemonadeNexusAttestdCore PUBLIC
        LemonadeNexus
        nlohmann_json::nlohmann_json
        spdlog)

# The target IS nexus-attestd: `cmake --build --target nexus-attestd` builds the
# daemon under every generator, and it is what the unit file and installed path
# name. A separate OUTPUT_NAME plus a same-named alias target would give Ninja
# two rules for one output path and abort generation, so there is neither.
add_executable(nexus-attestd src/main.cpp)
target_compile_features(nexus-attestd PRIVATE cxx_std_20)
target_link_libraries(nexus-attestd PRIVATE LemonadeNexusAttestdCore)

# Compiled-in version identity (values from cmake/version.cmake)
target_compile_definitions(nexus-attestd PRIVATE
        NEXUS_VERSION="${NEXUS_VERSION}"
        NEXUS_GIT_COMMIT="${NEXUS_GIT_COMMIT}")

if(NOT MSVC AND TARGET all_projects)
    add_dependencies(all_projects nexus-attestd)
endif()

install(TARGETS nexus-attestd
        RUNTIME DESTINATION bin
        COMPONENT Runtime)

if(UNIX AND NOT APPLE)
    # POSIX-only sources (unistd/dirent); keep the library, link, and probe
    # binary together under one guard so no other platform sees the target.
    add_library(Tier1AuthorityProbeCore src/Tier1AuthorityProbe.cpp)
    target_compile_features(Tier1AuthorityProbeCore PUBLIC cxx_std_20)
    target_include_directories(Tier1AuthorityProbeCore PUBLIC
            "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_link_libraries(LemonadeNexusAttestdCore PUBLIC Tier1AuthorityProbeCore)

    add_executable(nexus-tier1-authority-probe src/tier1_authority_probe_main.cpp)
    target_compile_features(nexus-tier1-authority-probe PRIVATE cxx_std_20)
    target_link_libraries(nexus-tier1-authority-probe PRIVATE Tier1AuthorityProbeCore)
    install(TARGETS nexus-tier1-authority-probe RUNTIME DESTINATION bin COMPONENT Runtime)
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/tier1-authority-probe.complete"
            DESTINATION lib/lemonade-nexus COMPONENT Runtime)
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/apparmor/nexus-tier1-authority-probe"
            DESTINATION /etc/apparmor.d COMPONENT Runtime)
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/apparmor/nexus-tier1-authority-probe.bin"
            DESTINATION lib/lemonade-nexus/apparmor COMPONENT Runtime)
    install(PROGRAMS "${CMAKE_SOURCE_DIR}/packaging/initramfs-tools/hooks/nexus-tier1-apparmor"
            DESTINATION share/initramfs-tools/hooks COMPONENT Runtime)
    install(PROGRAMS
            "${CMAKE_SOURCE_DIR}/packaging/initramfs-tools/scripts/init-premount/nexus-tier1-apparmor"
            DESTINATION share/initramfs-tools/scripts/init-premount COMPONENT Runtime)
    install(PROGRAMS
            "${CMAKE_SOURCE_DIR}/packaging/dracut/76nexus-tier1-apparmor/module-setup.sh"
            DESTINATION lib/dracut/modules.d/76nexus-tier1-apparmor COMPONENT Runtime)
    # Both backends execute the same loader source, keeping the securityfs
    # mount, pinned-blob load, and enforcing-state check identical.
    install(PROGRAMS
            "${CMAKE_SOURCE_DIR}/packaging/initramfs-tools/scripts/init-premount/nexus-tier1-apparmor"
            DESTINATION lib/dracut/modules.d/76nexus-tier1-apparmor
            RENAME nexus-tier1-apparmor.sh COMPONENT Runtime)
endif()

# The hardening in this unit is the point of the whole component; ship it with
# the binary rather than leaving the privilege boundary to a deployment note.
if(UNIX AND NOT APPLE)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/systemd/nexus-attestd.service"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/systemd/nexus-attestd-tsm-setup.service"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
    install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/systemd/nexus-attestd-tsm-setup"
            DESTINATION lib/lemonade-nexus
            COMPONENT Runtime)
endif()

# The server's platform source. The link lives here, not in LemonadeNexus, so
# there is no cycle: this project already depends on LemonadeNexus, and only the
# assembled executable depends on this one.
if(TARGET LemonadeNexusApp)
    target_link_libraries(LemonadeNexusApp PRIVATE LemonadeNexusAttestdCore)
    target_compile_definitions(LemonadeNexusApp PRIVATE LEMONADE_HAVE_ATTESTD_CLIENT)
endif()
