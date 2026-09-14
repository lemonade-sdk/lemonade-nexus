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

# The hardening in this unit is the point of the whole component; ship it with
# the binary rather than leaving the privilege boundary to a deployment note.
if(UNIX AND NOT APPLE)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/systemd/nexus-attestd.service"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
endif()

# The server's platform source. The link lives here, not in LemonadeNexus, so
# there is no cycle: this project already depends on LemonadeNexus, and only the
# assembled executable depends on this one.
if(TARGET LemonadeNexusApp)
    target_link_libraries(LemonadeNexusApp PRIVATE LemonadeNexusAttestdCore)
    target_compile_definitions(LemonadeNexusApp PRIVATE LEMONADE_HAVE_ATTESTD_CLIENT)
endif()
