# nexus-e2e: the live end-to-end test client (docs/Live-E2E.md). It drives the
# public SDK C ABI against the production fleet from the live-e2e workflow.
# It is a test tool: release builds set BUILD_TESTING=OFF, so it is never
# built into a package. CTest runs only its offline self-test.

add_executable(nexus-e2e nexus_e2e.cpp)
target_compile_features(nexus-e2e PRIVATE cxx_std_20)

# Link the shared library that applications load, so the test covers the
# exported C ABI. A build without it uses the static SDK, which has the same
# C ABI sources.
if(TARGET LemonadeNexusSDKShared)
    target_link_libraries(nexus-e2e PRIVATE LemonadeNexusSDKShared)
else()
    target_link_libraries(nexus-e2e PRIVATE LemonadeNexusSDK)
endif()

target_link_libraries(nexus-e2e PRIVATE
    nlohmann_json::nlohmann_json
    httplib::httplib
    sodium
    OpenSSL::SSL
    OpenSSL::Crypto)

add_test(NAME LiveE2E.SelfTest COMMAND nexus-e2e self-test)
