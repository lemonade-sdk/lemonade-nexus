cmake_minimum_required(VERSION 3.25.1)

include(ExternalProject)

# =============================================================================
# OpenSSL 3.3.2 — built from source via ExternalProject_Add
# =============================================================================
# OpenSSL uses its own Configure/make build system (not CMake), so we cannot
# use FetchContent.  Instead we build it as an external project and wire the
# resulting static libraries + headers into IMPORTED targets that behave
# exactly like find_package(OpenSSL) would.
# =============================================================================

set(OPENSSL_VERSION  "3.3.2")
set(OPENSSL_URL      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz")

# Install prefix inside the build tree — keeps things isolated.
set(OPENSSL_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/openssl-install")

# ---------------------------------------------------------------------------
# Platform-specific Configure target
# ---------------------------------------------------------------------------
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64|ARM64")
        set(OPENSSL_CONFIGURE_TARGET "darwin64-arm64-cc")
    else()
        set(OPENSSL_CONFIGURE_TARGET "darwin64-x86_64-cc")
    endif()
elseif(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(OPENSSL_CONFIGURE_TARGET "VC-WIN64A")
    else()
        set(OPENSSL_CONFIGURE_TARGET "VC-WIN32")
    endif()
else()
    # Linux / generic Unix
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        set(OPENSSL_CONFIGURE_TARGET "linux-x86_64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64|ARM64")
        set(OPENSSL_CONFIGURE_TARGET "linux-aarch64")
    else()
        # Fallback — let OpenSSL's Configure auto-detect
        set(OPENSSL_CONFIGURE_TARGET "")
    endif()
endif()

# ---------------------------------------------------------------------------
# Determine parallel job count for make
# ---------------------------------------------------------------------------
include(ProcessorCount)
ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 1)
endif()

# ---------------------------------------------------------------------------
# Platform-specific build commands
# ---------------------------------------------------------------------------
if(WIN32)
    set(_OPENSSL_CONFIGURE_CMD
        perl Configure ${OPENSSL_CONFIGURE_TARGET}
        --prefix=${OPENSSL_INSTALL_PREFIX}
        --openssldir=${OPENSSL_INSTALL_PREFIX}/ssl
        no-shared no-tests no-ui-console no-docs
    )
    set(_OPENSSL_BUILD_CMD nmake)
    set(_OPENSSL_INSTALL_CMD nmake install_sw)
    set(_SSL_LIB_NAME "libssl.lib")
    set(_CRYPTO_LIB_NAME "libcrypto.lib")
else()
    set(_OPENSSL_CONFIGURE_CMD
        ${CMAKE_COMMAND} -E env
        "CC=${CMAKE_C_COMPILER}"
        ./Configure ${OPENSSL_CONFIGURE_TARGET}
        --prefix=${OPENSSL_INSTALL_PREFIX}
        --openssldir=${OPENSSL_INSTALL_PREFIX}/ssl
        --libdir=lib
        no-shared no-tests no-ui-console no-docs
    )
    set(_OPENSSL_BUILD_CMD make -j${NPROC})
    set(_OPENSSL_INSTALL_CMD make install_sw)
    set(_SSL_LIB_NAME "libssl.a")
    set(_CRYPTO_LIB_NAME "libcrypto.a")
endif()

# ---------------------------------------------------------------------------
# Static library paths (where they'll end up after install_sw)
# ---------------------------------------------------------------------------
if(WIN32)
    set(OPENSSL_SSL_LIBRARY    "${OPENSSL_INSTALL_PREFIX}/lib/${_SSL_LIB_NAME}")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_PREFIX}/lib/${_CRYPTO_LIB_NAME}")
else()
    # OpenSSL 3.x installs to lib/ on most platforms; some 64-bit installs use lib64/
    set(OPENSSL_SSL_LIBRARY    "${OPENSSL_INSTALL_PREFIX}/lib/${_SSL_LIB_NAME}")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_PREFIX}/lib/${_CRYPTO_LIB_NAME}")
endif()
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_PREFIX}/include")

# ---------------------------------------------------------------------------
# ExternalProject_Add
# ---------------------------------------------------------------------------
ExternalProject_Add(openssl_external
    URL               ${OPENSSL_URL}
    URL_HASH          SHA256=2e8a40b01979afe8be0bbfb3de5dc1c6709fedb46d6c89c10da114ab5fc3d281
    DOWNLOAD_DIR      "${CMAKE_BINARY_DIR}/_download/openssl"
    SOURCE_DIR        "${CMAKE_BINARY_DIR}/_deps/openssl-src"
    BINARY_DIR        "${CMAKE_BINARY_DIR}/_deps/openssl-src"   # OpenSSL builds in-source
    INSTALL_DIR       "${OPENSSL_INSTALL_PREFIX}"
    CONFIGURE_COMMAND ${_OPENSSL_CONFIGURE_CMD}
    BUILD_COMMAND     ${_OPENSSL_BUILD_CMD}
    INSTALL_COMMAND   ${_OPENSSL_INSTALL_CMD}
    BUILD_BYPRODUCTS  ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
    LOG_DOWNLOAD      TRUE
    LOG_CONFIGURE     TRUE
    LOG_BUILD         TRUE
    LOG_INSTALL       TRUE
)

# ---------------------------------------------------------------------------
# IMPORTED targets that mimic find_package(OpenSSL)
# ---------------------------------------------------------------------------
# We create OpenSSL::Crypto and OpenSSL::SSL as IMPORTED STATIC libraries.
# All downstream targets (httplib, jwt-cpp, our own code) link against these.
# ---------------------------------------------------------------------------

# -- OpenSSL::Crypto --------------------------------------------------------
add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION             "${OPENSSL_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
)
add_dependencies(OpenSSL::Crypto openssl_external)

# -- OpenSSL::SSL -----------------------------------------------------------
add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION             "${OPENSSL_SSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
)
# SSL depends on Crypto
set_target_properties(OpenSSL::SSL PROPERTIES
    INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
)
add_dependencies(OpenSSL::SSL openssl_external)

# Platform link dependencies
if(APPLE)
    set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES "-framework Security" "-framework CoreFoundation")
elseif(UNIX)
    find_package(Threads REQUIRED)
    set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES Threads::Threads ${CMAKE_DL_LIBS})
elseif(WIN32)
    set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES ws2_32 crypt32)
endif()

# ---------------------------------------------------------------------------
# Set variables so that find_package(OpenSSL) in downstream CMakeLists.txt
# finds our built version instead of Homebrew / system OpenSSL.
# ---------------------------------------------------------------------------
set(OPENSSL_ROOT_DIR    "${OPENSSL_INSTALL_PREFIX}" CACHE PATH   "OpenSSL root (built from source)" FORCE)
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INCLUDE_DIR}"    CACHE PATH   "OpenSSL include directory"        FORCE)
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_CRYPTO_LIBRARY}" CACHE FILEPATH "OpenSSL crypto library"     FORCE)
set(OPENSSL_SSL_LIBRARY    "${OPENSSL_SSL_LIBRARY}"    CACHE FILEPATH "OpenSSL SSL library"        FORCE)
set(OPENSSL_FOUND       TRUE                        CACHE BOOL   "OpenSSL found"                   FORCE)
set(OPENSSL_VERSION     "${OPENSSL_VERSION}"         CACHE STRING "OpenSSL version"                 FORCE)

# Make the include directory exist at configure time so CMake doesn't
# complain about INTERFACE_INCLUDE_DIRECTORIES referencing a non-existent path.
file(MAKE_DIRECTORY "${OPENSSL_INCLUDE_DIR}")

message(STATUS "OpenSSL ${OPENSSL_VERSION} will be built from source → ${OPENSSL_INSTALL_PREFIX}")
