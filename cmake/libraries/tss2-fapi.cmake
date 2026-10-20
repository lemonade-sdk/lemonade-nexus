cmake_minimum_required(VERSION 3.25.1)

# =============================================================================
# tss2-fapi — TPM2 Software Stack, Feature API (libtss2-fapi)
# =============================================================================
# Provides <tss2/tss2_fapi.h>. Built from source via ExternalProject_Add
# (autotools), mirroring the OpenSSL pattern in libraries/openssl.cmake.
#
# FAPI is a Linux-only component and is built STATICALLY here. Its transitive
# dependencies are sourced as follows:
#   • OpenSSL  — the copy this repo builds from source (OpenSSL::Crypto)
#   • json-c   — system package, via pkg-config   (Debian: libjson-c-dev)
#   • libcurl  — system package, via pkg-config   (Debian: libcurl4-openssl-dev)
#   • libuuid  — system package, via pkg-config   (Debian: uuid-dev)
#
# We use the upstream *release tarball* (not a git clone) because it ships a
# pre-generated ./configure — so the build host only needs a C compiler, make
# and pkg-config, not the full autotools/autoconf-archive bootstrap chain.
#
# A `tss2::fapi` target is ALWAYS defined so the dependency list resolves on
# every platform. On Linux it carries the real include dirs + static libs and
# defines LEMONADE_HAVE_TPM_FAPI=1; on Windows/macOS it is an empty INTERFACE
# no-op. Guard TPM code with:
#     #ifdef LEMONADE_HAVE_TPM_FAPI
#       #include <tss2/tss2_fapi.h>
#       ...
#     #endif
#
# NOTE: static linking resolves the FAPI *API* at link time. To actually talk to
# a TPM at runtime, FAPI still needs a TCTI (e.g. device, swtpm) available on the
# deployment host — that is a runtime/deployment concern, not a build dep.
# =============================================================================

if(TARGET tss2::fapi)
    return()
endif()

if(LEMONADE_NEXUS_MINIMAL_DEPS OR NOT (UNIX AND NOT APPLE))
    # No-op target so the dependency list still resolves where FAPI is disabled.
    add_library(tss2_fapi_iface INTERFACE)
    add_library(tss2::fapi ALIAS tss2_fapi_iface)
    if(LEMONADE_NEXUS_MINIMAL_DEPS)
        message(STATUS "tss2-fapi: disabled by LEMONADE_NEXUS_MINIMAL_DEPS — building without TPM support")
    else()
        message(STATUS "tss2-fapi: TPM Feature API unavailable on this platform — building without TPM support")
    endif()
    return()
endif()

include(ExternalProject)
include(ProcessorCount)

# ---------------------------------------------------------------------------
# Transitive system deps (json-c, libcurl) — required for FAPI to configure.
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC IMPORTED_TARGET REQUIRED json-c)
pkg_check_modules(CURL  IMPORTED_TARGET REQUIRED libcurl)
pkg_check_modules(UUID  IMPORTED_TARGET REQUIRED uuid)

# OpenSSL is included before this module (see top-level CMakeLists.txt) and
# provides OpenSSL::Crypto. When built from source, OPENSSL_ROOT_DIR points at
# its install prefix; prepend its pkgconfig dir so tpm2-tss's ./configure finds
# our libcrypto rather than a system one.
set(_TSS2_PKGCONFIG_PATH "$ENV{PKG_CONFIG_PATH}")
set(_TSS2_CPPFLAGS "$ENV{CPPFLAGS}")
# TPM2-TSS bakes __FILE__ into its diagnostic strings; remap both trees so the
# compiled objects are build-directory-independent.
set(_TSS2_CFLAGS
    "-O2 -ffile-prefix-map=${CMAKE_BINARY_DIR}=build -ffile-prefix-map=${CMAKE_SOURCE_DIR}=source")
foreach(_TSS2_INCLUDE_DIR IN LISTS
        JSONC_INCLUDE_DIRS CURL_INCLUDE_DIRS UUID_INCLUDE_DIRS)
    string(APPEND _TSS2_CPPFLAGS " -I${_TSS2_INCLUDE_DIR}")
endforeach()
if(OPENSSL_ROOT_DIR)
    set(_TSS2_PKGCONFIG_PATH "${OPENSSL_ROOT_DIR}/lib/pkgconfig:${_TSS2_PKGCONFIG_PATH}")
endif()
set(_TSS2_ENV
    "PKG_CONFIG_PATH=${_TSS2_PKGCONFIG_PATH}"
    "CPPFLAGS=${_TSS2_CPPFLAGS}"
    "CFLAGS=${_TSS2_CFLAGS}"
    "CC=${CMAKE_C_COMPILER}")
foreach(_TSS2_VARIABLE IN ITEMS PKG_CONFIG_SYSROOT_DIR PKG_CONFIG_LIBDIR)
    if(NOT "$ENV{${_TSS2_VARIABLE}}" STREQUAL "")
        list(APPEND _TSS2_ENV "${_TSS2_VARIABLE}=$ENV{${_TSS2_VARIABLE}}")
    endif()
endforeach()

# ---------------------------------------------------------------------------
# Version / source
# ---------------------------------------------------------------------------
set(TSS2_VERSION "4.1.3")
set(TSS2_URL "https://github.com/tpm2-software/tpm2-tss/releases/download/${TSS2_VERSION}/tpm2-tss-${TSS2_VERSION}.tar.gz")
set(TSS2_URL_HASH "SHA256=37f1580200ab78305d1fc872d89241aaee0c93cbe85bc559bf332737a60d3be8")

set(TSS2_STAGE_ROOT     "${CMAKE_BINARY_DIR}/tss2-stage")
set(TSS2_INSTALL_PREFIX "${TSS2_STAGE_ROOT}/usr")
set(TSS2_INCLUDE_DIR    "${TSS2_INSTALL_PREFIX}/include")
set(TSS2_LIB_DIR        "${TSS2_INSTALL_PREFIX}/lib")

# Static archives produced by the build (link order matters: fapi → esys → sys
# → tctildr → mu → rc).
set(TSS2_FAPI_LIB    "${TSS2_LIB_DIR}/libtss2-fapi.a")
set(TSS2_ESYS_LIB    "${TSS2_LIB_DIR}/libtss2-esys.a")
set(TSS2_SYS_LIB     "${TSS2_LIB_DIR}/libtss2-sys.a")
set(TSS2_TCTILDR_LIB "${TSS2_LIB_DIR}/libtss2-tctildr.a")
set(TSS2_MU_LIB      "${TSS2_LIB_DIR}/libtss2-mu.a")
set(TSS2_RC_LIB      "${TSS2_LIB_DIR}/libtss2-rc.a")

ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 1)
endif()

# ---------------------------------------------------------------------------
# ExternalProject — autotools (configure / make / make install)
# ---------------------------------------------------------------------------
ExternalProject_Add(tss2_external
    URL               ${TSS2_URL}
    URL_HASH          ${TSS2_URL_HASH}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DOWNLOAD_DIR      "${CMAKE_BINARY_DIR}/_download/tss2"
    SOURCE_DIR        "${CMAKE_BINARY_DIR}/_deps/tss2-src"
    BINARY_DIR        "${CMAKE_BINARY_DIR}/_deps/tss2-build"   # out-of-source (VPATH) build
    INSTALL_DIR       "${TSS2_INSTALL_PREFIX}"
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
                      ${_TSS2_ENV}
                      <SOURCE_DIR>/configure
                      --prefix=/usr
                      --libdir=/usr/lib
                      --sysconfdir=/etc
                      --localstatedir=/var
                      --disable-shared --enable-static --with-pic
                      --enable-fapi
                      --with-crypto=ossl
                      --disable-doxygen-doc
                      --disable-unit
                      --disable-integration
    BUILD_COMMAND     make -j${NPROC}
    INSTALL_COMMAND   make DESTDIR=${TSS2_STAGE_ROOT} install
    BUILD_BYPRODUCTS  ${TSS2_FAPI_LIB} ${TSS2_ESYS_LIB} ${TSS2_SYS_LIB}
                      ${TSS2_TCTILDR_LIB} ${TSS2_MU_LIB} ${TSS2_RC_LIB}
    LOG_DOWNLOAD      TRUE
    LOG_CONFIGURE     TRUE
    LOG_BUILD         TRUE
    LOG_INSTALL       TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)

# Build OpenSSL first if it's also built from source.
if(TARGET openssl_external)
    add_dependencies(tss2_external openssl_external)
endif()

# Include dir must exist at configure time so CMake doesn't complain about
# INTERFACE_INCLUDE_DIRECTORIES referencing a non-existent path.
file(MAKE_DIRECTORY "${TSS2_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# IMPORTED target: tss2::fapi
# ---------------------------------------------------------------------------
add_library(tss2::fapi STATIC IMPORTED GLOBAL)
set_target_properties(tss2::fapi PROPERTIES
    IMPORTED_LOCATION             "${TSS2_FAPI_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${TSS2_INCLUDE_DIR}"
    INTERFACE_COMPILE_DEFINITIONS "LEMONADE_HAVE_TPM_FAPI=1"
)

find_package(Threads REQUIRED)

# Remaining tss2 archives + transitive deps, in link order.
set_target_properties(tss2::fapi PROPERTIES
    INTERFACE_LINK_LIBRARIES
        "${TSS2_ESYS_LIB};${TSS2_SYS_LIB};${TSS2_TCTILDR_LIB};${TSS2_MU_LIB};${TSS2_RC_LIB};OpenSSL::Crypto;PkgConfig::CURL;PkgConfig::JSONC;PkgConfig::UUID;Threads::Threads;${CMAKE_DL_LIBS}"
)
add_dependencies(tss2::fapi tss2_external)

message(STATUS "tss2-fapi ${TSS2_VERSION} will be built from source → ${TSS2_INSTALL_PREFIX}")
