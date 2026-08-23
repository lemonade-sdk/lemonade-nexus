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
    if(WIN32)
        target_link_libraries(${TEST_NAME} PRIVATE ws2_32 mswsock iphlpapi)
    endif()
    gtest_discover_tests(${TEST_NAME})
endfunction()

# --- Unit tests ---
add_nexus_test(test_version            test_version.cpp)
add_nexus_test(test_crypto_types       test_crypto_types.cpp)
add_nexus_test(test_sodium_crypto      test_sodium_crypto.cpp)
add_nexus_test(test_key_wrapping       test_key_wrapping.cpp)
add_nexus_test(test_file_storage       test_file_storage.cpp)
add_nexus_test(test_permissions        test_permissions.cpp)
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

add_nexus_test(test_trust             test_trust.cpp)
add_nexus_test(test_onboarding        test_onboarding.cpp)
add_nexus_test(test_tls_resolution    test_tls_resolution.cpp)

# Uses httplib SSLClient/SSLServer + OpenSSL X509 directly for the TLS transport test.
add_nexus_test(test_tls_transport     test_tls_transport.cpp)
target_compile_definitions(test_tls_transport PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(test_tls_transport PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_nexus_test(test_tee_attestation_tpm test_tee_attestation_tpm.cpp)

# Drives the SNP evidence chain against a real attestation blob + VCEK captured from
# the live Azure genesis, so it runs with no confidential-compute hardware present.
add_nexus_test(test_snp_evidence      test_snp_evidence.cpp)
target_compile_definitions(test_snp_evidence PRIVATE
    NEXUS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

# The links above the AMD signature: the quote under HCLAkPub, the evidence
# binding, and the IMA replay.
add_nexus_test(test_evidence_chain    test_evidence_chain.cpp)
target_compile_definitions(test_evidence_chain PRIVATE
    NEXUS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
add_nexus_test(test_misbehavior_detector test_misbehavior_detector.cpp)

# --- Security overhaul tests (mirror include/LemonadeNexus/Security/) ---
add_nexus_test(test_security_policy
    security/policy/quorum.cpp
    security/policy/tier1_target.cpp
    security/policy/tier1_eligibility.cpp
    security/policy/canonical_encoding.cpp)
add_nexus_test(test_secure_buffer      test_secure_buffer.cpp)
add_nexus_test(test_security_consensus
    security/consensus/consensus_types.cpp
    security/consensus/quorum_certificate.cpp
    security/consensus/leader_selection.cpp
    security/consensus/pacemaker.cpp)
add_nexus_test(test_security_epoch
    security/epoch/tier1_selector.cpp
    security/epoch/epoch_state.cpp
    security/epoch/transition.cpp)
# Temporary guard: the HotStuff service sources land from a parallel task.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/security/consensus/hotstuff_restart.cpp)
add_nexus_test(test_security_hotstuff
    security/consensus/consensus_store.cpp
    security/consensus/hotstuff_safety.cpp
    security/consensus/hotstuff_votes.cpp
    security/consensus/hotstuff_restart.cpp)
endif()
add_nexus_test(test_security_genesis
    security/genesis/genesis.cpp)
add_nexus_test(test_security_authority
    security/authority/authority_object.cpp
    security/authority/nonce_commitment.cpp)
add_nexus_test(test_security_attestation
    security/attestation/challenge.cpp
    security/attestation/verifier.cpp
    security/attestation/linux_profile.cpp)

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
    gtest_discover_tests(${TEST_NAME})
endfunction()

add_sdk_test(test_routing_pool         test_routing_pool.cpp)
add_sdk_test(test_mesh_ingress         test_mesh_ingress.cpp)
add_sdk_test(test_boringtun_keys       test_boringtun_keys.cpp)
add_sdk_test(test_group_key_envelope   test_group_key_envelope.cpp)

# --- Integration tests ---
add_nexus_test(test_http_endpoints     test_http_endpoints.cpp)
add_nexus_test(test_virtual_e2e        test_virtual_e2e.cpp)
