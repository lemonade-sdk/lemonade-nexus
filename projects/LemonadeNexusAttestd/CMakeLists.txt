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

add_executable(LemonadeNexusAttestd src/main.cpp)
set_target_properties(LemonadeNexusAttestd PROPERTIES OUTPUT_NAME "nexus-attestd")
target_compile_features(LemonadeNexusAttestd PRIVATE cxx_std_20)
target_link_libraries(LemonadeNexusAttestd PRIVATE LemonadeNexusAttestdCore)

# Compiled-in version identity (values from cmake/version.cmake)
target_compile_definitions(LemonadeNexusAttestd PRIVATE
        NEXUS_VERSION="${NEXUS_VERSION}"
        NEXUS_GIT_COMMIT="${NEXUS_GIT_COMMIT}")

# Build alias, so `cmake --build build --target nexus-attestd` names the same
# thing the installed binary and the unit file do.
add_custom_target(nexus-attestd DEPENDS LemonadeNexusAttestd)

if(NOT MSVC AND TARGET all_projects)
    add_dependencies(all_projects LemonadeNexusAttestd)
endif()

install(TARGETS LemonadeNexusAttestd
        RUNTIME DESTINATION bin
        COMPONENT Runtime)

# The hardening in this unit is the point of the whole component; ship it with
# the binary rather than leaving the privilege boundary to a deployment note.
if(UNIX AND NOT APPLE)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/systemd/nexus-attestd.service"
            DESTINATION lib/systemd/system
            COMPONENT Runtime)
endif()
