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

# Tier 1 membership verification (Tier1Directory.cpp) reuses the server's own
# authority chain verifier and codec, and the server's list of tree routes,
# so the client and the server check the same rules. These sources depend on
# libsodium, nlohmann_json, and httplib only.
set(LN_SERVER_SRC "${CMAKE_SOURCE_DIR}/projects/LemonadeNexus/src")
set(LN_TRUST_SRC
    "${LN_SERVER_SRC}/Api/TreeRouteGate.cpp"
    "${LN_SERVER_SRC}/Crypto/CryptoTypes.cpp"
    "${LN_SERVER_SRC}/Crypto/SecureBuffer.cpp"
    "${LN_SERVER_SRC}/Security/CanonicalEncoding.cpp"
    "${LN_SERVER_SRC}/Security/Consensus/CommitProof.cpp"
    "${LN_SERVER_SRC}/Security/Consensus/ConsensusTypes.cpp"
    "${LN_SERVER_SRC}/Security/Consensus/QuorumValidation.cpp"
    "${LN_SERVER_SRC}/Security/Consensus/VoteKey.cpp"
    "${LN_SERVER_SRC}/Security/Epoch/AuthorityChain.cpp"
    "${LN_SERVER_SRC}/Security/Epoch/NextEpochPlan.cpp"
    "${LN_SERVER_SRC}/Security/Epoch/Tier1Membership.cpp"
    "${LN_SERVER_SRC}/Security/Epoch/Tier1Set.cpp"
    "${LN_SERVER_SRC}/Security/Genesis/BootstrapCertificate.cpp"
    "${LN_SERVER_SRC}/Security/Transport/AuthorityChainCodec.cpp")

# Relay fallback (RelayChannel.cpp, BoringtunMesh.cpp) speaks the relay's own
# wire codec and rendezvous derivation, so the client and the relay encode
# the same bytes. It depends on libsodium, nlohmann_json, and the trust
# sources above only.
list(APPEND LN_TRUST_SRC "${LN_SERVER_SRC}/Relay/RelayWire.cpp")

# Reflexive-address learning (BoringtunMesh.cpp) and the dataplane's STUN
# demultiplexing (UserspaceDataplane.cpp) use the STUN codec of the server's
# StunService, so both sides encode the same bytes. No dependencies.
list(APPEND LN_TRUST_SRC "${LN_SERVER_SRC}/Network/StunWire.cpp")

# The mesh port (MeshPort.cpp) folds device names to DNS labels with the
# server's rule, the one the tree applies when it refuses two devices of a
# group that fold to the same label. No dependencies.
list(APPEND LN_TRUST_SRC "${LN_SERVER_SRC}/Tree/DeviceLabel.cpp")

# The per-user identity store (IdentityStore_<os>.cpp) keeps its key in the
# OS keystore: the login keychain on macOS (Security and CoreFoundation),
# DPAPI on Windows (crypt32), and libsecret on Linux, which is loaded at run
# time with dlopen so there is no build-time or package dependency on it.
# LAN-direct paths (LanPaths_windows.cpp) list the network adapters with
# GetAdaptersAddresses on Windows (iphlpapi); POSIX uses getifaddrs from libc.
if(APPLE)
    set(LN_PLATFORM_LIBS "-framework Security" "-framework CoreFoundation")
elseif(WIN32)
    set(LN_PLATFORM_LIBS crypt32 iphlpapi ws2_32)
else()
    set(LN_PLATFORM_LIBS ${CMAKE_DL_LIBS})
endif()

if(TARGET LemonadeNexusSDK)
    target_sources(LemonadeNexusSDK PRIVATE "${LN_DATAPLANE_SRC}" ${LN_TRUST_SRC})
    target_include_directories(LemonadeNexusSDK PRIVATE "${LN_SERVER_INCLUDE}")
    target_link_libraries(LemonadeNexusSDK PUBLIC virtual-netstack ${LN_PLATFORM_LIBS})
endif()
if(TARGET LemonadeNexusSDKApp)
    target_sources(LemonadeNexusSDKApp PRIVATE "${LN_DATAPLANE_SRC}" ${LN_TRUST_SRC})
    target_include_directories(LemonadeNexusSDKApp PRIVATE "${LN_SERVER_INCLUDE}")
    target_link_libraries(LemonadeNexusSDKApp PUBLIC virtual-netstack ${LN_PLATFORM_LIBS})
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
    list(APPEND _sdk_shared_sources "${LN_DATAPLANE_SRC}" ${LN_TRUST_SRC})

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
            virtual-netstack
            ${LN_PLATFORM_LIBS})

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

    # iOS apps load a dynamic library only from a framework bundle in the
    # app's Frameworks directory: lemonade_nexus_sdk.framework, packed into an
    # XCFramework by scripts/build-sdk-mobile.sh.
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set_target_properties(LemonadeNexusSDKShared PROPERTIES
                FRAMEWORK TRUE
                MACOSX_FRAMEWORK_IDENTIFIER io.lemonade-nexus.sdk
                MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${PROJECT_VERSION}"
                MACOSX_FRAMEWORK_BUNDLE_VERSION "${PROJECT_VERSION}"
                MACOSX_FRAMEWORK_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/ios/Info.plist.in")
    endif()

    # The visibility preset hides only the SDK's own code; symbols from the
    # static OpenSSL and Rust archives would still be exported. On the mobile
    # builds export the ln_* API alone, so an app that also bundles OpenSSL or
    # BoringSSL cannot bind to this copy (Android resolves symbols in one flat
    # namespace).
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        target_link_options(LemonadeNexusSDKShared PRIVATE "LINKER:-exported_symbol,_ln_*")
    elseif(ANDROID)
        target_link_options(LemonadeNexusSDKShared PRIVATE "LINKER:--exclude-libs,ALL")
    endif()

    if(NOT MSVC AND TARGET all_projects)
        add_dependencies(all_projects LemonadeNexusSDKShared)
    endif()
endif()
