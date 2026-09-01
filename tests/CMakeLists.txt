cmake_minimum_required(VERSION 3.25.1)

include(GoogleTest)

# Helper: create a test executable linked to the main library + GTest
function(add_nexus_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE
        LemonadeNexus
        GTest::gtest_main
        GTest::gmock
    )
    target_compile_definitions(${TEST_NAME} PRIVATE
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
    )
    # Shared test-only headers live under tests/support.
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(WIN32)
        target_link_libraries(${TEST_NAME} PRIVATE ws2_32 mswsock iphlpapi)
    endif()
    # Listing a large binary on a loaded machine can exceed the 5 s default;
    # a timeout deletes the executable and registers a NOT_BUILT placeholder.
    gtest_discover_tests(${TEST_NAME} DISCOVERY_TIMEOUT 120)
endfunction()

# --- Unit tests ---
add_nexus_test(test_version            test_version.cpp)
add_nexus_test(test_crypto_types       test_crypto_types.cpp)
add_nexus_test(test_sodium_crypto      test_sodium_crypto.cpp)
add_nexus_test(test_key_wrapping       test_key_wrapping.cpp)
add_nexus_test(test_file_storage       test_file_storage.cpp)
add_nexus_test(test_permission_tree    test_permission_tree.cpp)
add_nexus_test(test_account_data       test_account_data.cpp)
add_nexus_test(test_mesh_rekey         test_mesh_rekey.cpp)
add_nexus_test(test_routing_identifier test_routing_identifier.cpp)
add_nexus_test(test_routing_coordination test_routing_coordination.cpp)
add_nexus_test(test_routing_security  test_routing_security.cpp)
add_nexus_test(test_rate_limiter       test_rate_limiter.cpp)
add_nexus_test(test_ipam              test_ipam.cpp)
add_nexus_test(test_auth              test_auth.cpp)
add_nexus_test(test_acme              test_acme.cpp)
add_nexus_test(test_dns               test_dns.cpp)
add_nexus_test(test_geo_region        test_geo_region.cpp)
add_nexus_test(test_seed_discovery    test_seed_discovery.cpp)

add_nexus_test(test_wg_wire_protocol  test_wg_wire_protocol.cpp)
add_nexus_test(test_ip_router         test_ip_router.cpp)
add_nexus_test(test_userspace_dataplane test_userspace_dataplane.cpp)

add_nexus_test(test_tls_resolution    test_tls_resolution.cpp)
add_nexus_test(test_onboarding        test_onboarding.cpp)

# Uses httplib SSLClient/SSLServer + OpenSSL X509 directly for the TLS transport test.
add_nexus_test(test_tls_transport     test_tls_transport.cpp)
target_compile_definitions(test_tls_transport PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(test_tls_transport PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Drives the SNP evidence chain against a real attestation blob + VCEK captured from
# the live Azure genesis, so it runs with no confidential-compute hardware present.
add_nexus_test(test_snp_evidence      test_snp_evidence.cpp)
target_compile_definitions(test_snp_evidence PRIVATE
    NEXUS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

# Real SEV-SNP bytes from our own Genoa host: the only tests that assert the
# AMD chain ACCEPTS evidence rather than rejecting it.
add_nexus_test(test_snp_genoa         test_snp_genoa.cpp)
target_compile_definitions(test_snp_genoa PRIVATE
    NEXUS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
target_link_libraries(test_snp_genoa PRIVATE OpenSSL::Crypto)

# The links above the AMD signature: the quote under HCLAkPub, the evidence
# binding, and the IMA replay.
add_nexus_test(test_evidence_chain    test_evidence_chain.cpp)
target_compile_definitions(test_evidence_chain PRIVATE
    NEXUS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
add_nexus_test(test_misbehavior_detector test_misbehavior_detector.cpp)
add_nexus_test(test_legacy_removal    test_legacy_removal.cpp)
# Hostile packets at the real wire boundary: cert-gated sync, ServerHello
# proof-of-possession, misbehavior proofs, and NS slot claim laundering.
add_nexus_test(test_gossip_ingress_security test_gossip_ingress_security.cpp)
add_nexus_test(test_gossip_security_transport test_gossip_security_transport.cpp)
add_nexus_test(test_security_mesh_service test_security_mesh_service.cpp)

# --- Security overhaul tests (mirror include/LemonadeNexus/Security/) ---
add_nexus_test(test_security_policy
    security/policy/quorum.cpp
    security/policy/tier1_target.cpp
    security/policy/tier1_eligibility.cpp
    security/policy/tier1_evidence.cpp
    security/policy/canonical_encoding.cpp)
add_nexus_test(test_secure_buffer      test_secure_buffer.cpp)
add_nexus_test(test_frost_provider     test_frost_provider.cpp)
add_nexus_test(test_security_consensus
    security/consensus/consensus_types.cpp
    security/consensus/quorum_certificate.cpp
    security/consensus/leader_selection.cpp
    security/consensus/pacemaker.cpp)
add_nexus_test(test_security_epoch
    security/epoch/tier1_selector.cpp
    security/epoch/epoch_state.cpp
    security/epoch/transition.cpp
    security/epoch/epoch_manager.cpp
    security/epoch/epoch_store.cpp)
add_nexus_test(test_security_hotstuff
    security/consensus/consensus_store.cpp
    security/consensus/hotstuff_safety.cpp
    security/consensus/hotstuff_votes.cpp
    security/consensus/hotstuff_restart.cpp)
add_nexus_test(test_security_integration
    security/integration/first_path.cpp)
add_nexus_test(test_security_transport
    security/transport/codec.cpp
    security/transport/router.cpp)
add_nexus_test(test_security_lifecycle
    security/lifecycle/driver.cpp
    security/lifecycle/eligibility_path.cpp
    security/lifecycle/tier2_path.cpp
    security/lifecycle/adoption_path.cpp
    security/lifecycle/adversarial.cpp)
add_nexus_test(test_security_genesis
    security/genesis/genesis.cpp)
add_nexus_test(test_security_authority
    security/authority/authority_object.cpp
    security/authority/nonce_commitment.cpp
    security/authority/dkg_session.cpp
    security/authority/signing.cpp)
add_nexus_test(test_security_eligibility
    security/eligibility/ledger.cpp
    security/eligibility/store.cpp
    security/eligibility/service.cpp)
# Deterministic measurement across the Tier 1 population table. Records what
# the protocol costs at 5 and at 31; asserts invariants only, never a tuned
# threshold.
add_nexus_test(test_security_scale
    security/simulation/scale.cpp
    security/simulation/eligibility_scale.cpp)
add_nexus_test(test_security_attestation
    security/attestation/challenge.cpp
    security/attestation/verifier.cpp
    security/attestation/linux_profile.cpp
    security/attestation/service.cpp
    security/attestation/producer.cpp
    security/attestation/providers.cpp
    security/attestation/tier1_path.cpp)
# providers.cpp runs the substitution negatives against the captured SNP blob.
target_compile_definitions(test_security_attestation PRIVATE
    NEXUS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

# --- Parser fuzzing ---
#
# The targets run two ways. corpus_replay drives them from a fixed corpus in
# the normal suite, so they stay compiled and exercised on every build. With
# NEXUS_BUILD_FUZZERS=ON and a clang that has libFuzzer, each target also
# builds as its own fuzzer binary.
add_nexus_test(test_fuzz_corpus fuzz/corpus_replay.cpp)

option(NEXUS_BUILD_FUZZERS "Build libFuzzer targets for the security parsers" OFF)
if(NEXUS_BUILD_FUZZERS)
    # AppleClang ships no libFuzzer runtime. Detect it here so the failure is a
    # clear message at configure time rather than a missing archive at link.
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
    check_cxx_source_compiles(
        "#include <cstdint>\n#include <cstddef>\n
         extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }"
        NEXUS_HAVE_LIBFUZZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if(NOT NEXUS_HAVE_LIBFUZZER)
        message(FATAL_ERROR
            "NEXUS_BUILD_FUZZERS=ON but this toolchain has no libFuzzer runtime. "
            "Use a clang built with compiler-rt fuzzer support "
            "(AppleClang does not ship one). The targets still run from a fixed "
            "corpus in test_fuzz_corpus without it.")
    endif()
    set(NEXUS_FUZZ_TARGETS
        security_envelope snp_report hcl_blob tpm_quote tpmt_signature
        ima_log amd_crl amd_certificate platform_evidence_json
        eligibility_observation participation_response)
    foreach(target ${NEXUS_FUZZ_TARGETS})
        add_executable(fuzz_${target} fuzz/libfuzzer_main.cpp)
        target_link_libraries(fuzz_${target} PRIVATE LemonadeNexus)
        target_include_directories(fuzz_${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(fuzz_${target} PRIVATE
            ASIO_STANDALONE ASIO_NO_DEPRECATED
            NEXUS_FUZZ_TARGET=fuzz_${target})
        target_compile_options(fuzz_${target} PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()

# --- SDK tests (link against LemonadeNexusSDK) ---
function(add_sdk_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE
        LemonadeNexusSDK
        GTest::gtest_main
        GTest::gmock
    )
    if(WIN32)
        target_link_libraries(${TEST_NAME} PRIVATE ws2_32 mswsock iphlpapi)
    endif()
    # Listing a large binary on a loaded machine can exceed the 5 s default;
    # a timeout deletes the executable and registers a NOT_BUILT placeholder.
    gtest_discover_tests(${TEST_NAME} DISCOVERY_TIMEOUT 120)
endfunction()

add_sdk_test(test_routing_pool         test_routing_pool.cpp)
add_sdk_test(test_mesh_ingress         test_mesh_ingress.cpp)
add_sdk_test(test_boringtun_keys       test_boringtun_keys.cpp)
add_sdk_test(test_group_key_envelope   test_group_key_envelope.cpp)

# --- Integration tests ---
add_nexus_test(test_http_endpoints     test_http_endpoints.cpp)
add_nexus_test(test_virtual_e2e        test_virtual_e2e.cpp)
