cmake_minimum_required(VERSION 3.25.1)
include(CreateProject)

# OpenSSL::SSL and OpenSSL::Crypto are provided by cmake/libraries/openssl.cmake
# (built from source via ExternalProject_Add — no system/Homebrew dependency).

create_project(LemonadeNexusSDK DEPENDENCIES
        nlohmann_json::nlohmann_json
        spdlog
        httplib::httplib
        sodium
        OpenSSL::SSL
        OpenSSL::Crypto
        boringtun-ffi
)

# The userspace boringtun dataplane lives in the server project; the SDK's
# BoringtunMesh (BoringtunMesh.cpp) joins it to the virtual netstack to carry
# mesh P2P traffic and egress the private API as loopback sockets (no TUN
# device). Compile the dataplane into the SDK, expose the server include path,
# and link the netstack.
set(LN_DATAPLANE_SRC "${CMAKE_SOURCE_DIR}/projects/LemonadeNexus/src/Boringtun/UserspaceDataplane.cpp")
set(LN_SERVER_INCLUDE "${CMAKE_SOURCE_DIR}/projects/LemonadeNexus/include")
if(TARGET LemonadeNexusSDK)
    target_sources(LemonadeNexusSDK PRIVATE "${LN_DATAPLANE_SRC}")
    target_include_directories(LemonadeNexusSDK PRIVATE "${LN_SERVER_INCLUDE}")
    target_link_libraries(LemonadeNexusSDK PUBLIC virtual-netstack)
endif()
if(TARGET LemonadeNexusSDKApp)
    target_sources(LemonadeNexusSDKApp PRIVATE "${LN_DATAPLANE_SRC}")
    target_include_directories(LemonadeNexusSDKApp PRIVATE "${LN_SERVER_INCLUDE}")
    target_link_libraries(LemonadeNexusSDKApp PUBLIC virtual-netstack)
endif()

# ---------------------------------------------------------------------------
# Shared library for FFI (Flutter desktop clients on macOS/Windows/Linux).
#
# Produces a single self-contained shared library (liblemonade_nexus_sdk.dylib
# / lemonade_nexus_sdk.dll / liblemonade_nexus_sdk.so) that embeds all static
# dependencies (OpenSSL, libsodium, boringtun-ffi, ...) so the only runtime
# dependencies are system libraries. The Dart FFI layer loads it by leaf name
# `lemonade_nexus_sdk`. Only the ln_* C API is exported (see the visibility
# pragmas in include/LemonadeNexusSDK/lemonade_nexus.h).
# ---------------------------------------------------------------------------
option(BUILD_SDK_SHARED "Build LemonadeNexusSDK as a self-contained shared library for FFI" ON)
if(BUILD_SDK_SHARED)
    file(GLOB_RECURSE _sdk_shared_sources "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
    list(REMOVE_ITEM _sdk_shared_sources "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
    list(APPEND _sdk_shared_sources "${LN_DATAPLANE_SRC}")

    add_library(LemonadeNexusSDKShared SHARED ${_sdk_shared_sources})
    target_compile_features(LemonadeNexusSDKShared PUBLIC cxx_std_20)
    target_include_directories(LemonadeNexusSDKShared PUBLIC
            "${CMAKE_CURRENT_SOURCE_DIR}/include"
            "${CMAKE_CURRENT_BINARY_DIR}/include")
    target_include_directories(LemonadeNexusSDKShared PRIVATE "${LN_SERVER_INCLUDE}")
    target_link_libraries(LemonadeNexusSDKShared PRIVATE
            nlohmann_json::nlohmann_json
            spdlog
            httplib::httplib
            sodium
            OpenSSL::SSL
            OpenSSL::Crypto
            boringtun-ffi
            virtual-netstack)

    # Tells the header which build this is (used for __declspec on MSVC if ever needed).
    target_compile_definitions(LemonadeNexusSDKShared PRIVATE LN_BUILD_SHARED)

    set_target_properties(LemonadeNexusSDKShared PROPERTIES
            OUTPUT_NAME lemonade_nexus_sdk
            # Hide everything except the ln_* C API (marked default in the header).
            C_VISIBILITY_PRESET hidden
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
            # MSVC has no visibility attributes; export the C API via an auto .def.
            WINDOWS_EXPORT_ALL_SYMBOLS ON
            # macOS: resolve by @rpath so the dylib can live in the app's Frameworks dir.
            MACOSX_RPATH ON
            INSTALL_NAME_DIR "@rpath")

    if(NOT MSVC AND TARGET all_projects)
        add_dependencies(all_projects LemonadeNexusSDKShared)
    endif()
endif()
