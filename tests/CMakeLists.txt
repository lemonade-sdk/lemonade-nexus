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
add_nexus_test(test_crypto_types       test_crypto_types.cpp)
add_nexus_test(test_sodium_crypto      test_sodium_crypto.cpp)
add_nexus_test(test_key_wrapping       test_key_wrapping.cpp)
add_nexus_test(test_file_storage       test_file_storage.cpp)
add_nexus_test(test_permissions        test_permissions.cpp)
add_nexus_test(test_permission_tree    test_permission_tree.cpp)
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
add_nexus_test(test_tee_attestation_tpm test_tee_attestation_tpm.cpp)
add_nexus_test(test_misbehavior_detector test_misbehavior_detector.cpp)

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

add_sdk_test(test_boringtun_backend    test_boringtun_backend.cpp)

# --- Integration tests ---
add_nexus_test(test_http_endpoints     test_http_endpoints.cpp)
add_nexus_test(test_virtual_e2e        test_virtual_e2e.cpp)
