cmake_minimum_required(VERSION 3.25.1)

# Headless mesh-client binary that embeds the SDK. Links the LemonadeNexusSDK
# static library (built by projects/LemonadeNexusSDK) plus its transitive deps
# (httplib, sodium, boringtun, virtual-netstack, OpenSSL).

add_executable(LemonadeNexusSidecar src/main.cpp)
set_target_properties(LemonadeNexusSidecar PROPERTIES OUTPUT_NAME "lemonade-nexus-sidecar")

target_compile_features(LemonadeNexusSidecar PRIVATE cxx_std_20)
target_link_libraries(LemonadeNexusSidecar PRIVATE
        LemonadeNexusSDK
        httplib::httplib
        nlohmann_json::nlohmann_json
        spdlog)

# Compiled-in version identity (values from cmake/version.cmake)
target_compile_definitions(LemonadeNexusSidecar PRIVATE
        NEXUS_VERSION="${NEXUS_VERSION}"
        NEXUS_GIT_COMMIT="${NEXUS_GIT_COMMIT}")

if(WIN32)
    target_link_libraries(LemonadeNexusSidecar PRIVATE ws2_32 mswsock iphlpapi)
endif()

if(NOT MSVC AND TARGET all_projects)
    add_dependencies(all_projects LemonadeNexusSidecar)
endif()

install(TARGETS LemonadeNexusSidecar
        RUNTIME DESTINATION bin
        COMPONENT Runtime)
