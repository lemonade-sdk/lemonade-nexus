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
    gtest_discover_tests(${TEST_NAME})
endfunction()

# --- Unit tests ---
add_nexus_test(test_crypto_types       test_crypto_types.cpp)
add_nexus_test(test_sodium_crypto      test_sodium_crypto.cpp)
add_nexus_test(test_key_wrapping       test_key_wrapping.cpp)
add_nexus_test(test_file_storage       test_file_storage.cpp)
add_nexus_test(test_permissions        test_permissions.cpp)
add_nexus_test(test_permission_tree    test_permission_tree.cpp)
add_nexus_test(test_rate_limiter       test_rate_limiter.cpp)
add_nexus_test(test_ipam              test_ipam.cpp)
add_nexus_test(test_auth              test_auth.cpp)
add_nexus_test(test_acme              test_acme.cpp)
add_nexus_test(test_dns               test_dns.cpp)
add_nexus_test(test_geo_region        test_geo_region.cpp)

add_nexus_test(test_trust             test_trust.cpp)

# --- Integration tests ---
add_nexus_test(test_http_endpoints     test_http_endpoints.cpp)
