# =============================================================================
# CPack Packaging Configuration
# =============================================================================
# Usage:
#   cmake --build build
#   cpack --config build/CPackConfig.cmake          # default generator(s)
#   cpack --config build/CPackConfig.cmake -G DEB   # specific generator
#   cpack --config build/CPackConfig.cmake -G RPM
#   cpack --config build/CPackConfig.cmake -G productbuild   # macOS .pkg
#   cpack --config build/CPackConfig.cmake -G NSIS           # Windows .exe
# =============================================================================

# ── Package metadata ─────────────────────────────────────────────────────────

set(CPACK_PACKAGE_NAME "lemonade-nexus")
set(CPACK_PACKAGE_VENDOR "Lemonade-Nexus")

# Derive version from git tag (e.g. v0.3.0-alpha -> 0.3.0-alpha), fallback to 0.1.0
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

# Accept version override from CI (e.g. -DGIT_TAG_OVERRIDE=v0.4.0-alpha)
if(GIT_TAG_OVERRIDE)
    string(REGEX REPLACE "^v" "" GIT_VERSION "${GIT_TAG_OVERRIDE}")
    set(CPACK_PACKAGE_VERSION "${GIT_VERSION}")
    message(STATUS "Packaging version from GIT_TAG_OVERRIDE: ${CPACK_PACKAGE_VERSION}")
else()
    execute_process(
        COMMAND git describe --tags --exact-match HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_TAG
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE GIT_TAG_RESULT
    )
    if(GIT_TAG_RESULT EQUAL 0 AND GIT_TAG)
        # Strip leading 'v' if present (v0.3.0-alpha -> 0.3.0-alpha)
        string(REGEX REPLACE "^v" "" GIT_VERSION "${GIT_TAG}")
        set(CPACK_PACKAGE_VERSION "${GIT_VERSION}")
        message(STATUS "Packaging version from git tag: ${CPACK_PACKAGE_VERSION}")
    endif()
endif()
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Self-hosted WireGuard mesh VPN server")
set(CPACK_PACKAGE_DESCRIPTION
    "Cryptographically secure, self-hosted WireGuard mesh VPN with Ed25519 identity, gossip-based state sync, distributed authoritative DNS, TEE attestation, and zero-trust enrollment.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/geramyloveless/lemonade-nexus")
set(CPACK_PACKAGE_CONTACT "admin@lemonade-nexus.io")

if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

# ── Platform detection for default generators ────────────────────────────────

if(WIN32)
    set(CPACK_GENERATOR "NSIS;ZIP")
elseif(APPLE)
    set(CPACK_GENERATOR "productbuild;TGZ")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
endif()

# ── File naming ──────────────────────────────────────────────────────────────

# Output: lemonade-nexus-0.1.0-Linux.deb, lemonade-nexus-0.1.0-Darwin.pkg, etc.
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

# Strip binaries in release packages
set(CPACK_STRIP_FILES ON)

# ── DEB (Debian/Ubuntu) ─────────────────────────────────────────────────────

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lemonade-Nexus Team <admin@lemonade-nexus.io>")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3 | libssl1.1")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/packaging/debian/postinst;${CMAKE_SOURCE_DIR}/packaging/debian/prerm")

# ── RPM (Fedora/RHEL/CentOS) ────────────────────────────────────────────────

set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set(CPACK_RPM_PACKAGE_REQUIRES "openssl-libs")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/debian/postinst")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/debian/prerm")
# Don't package build ID files (avoids conflicts with debuginfo packages)
set(CPACK_RPM_SPEC_MORE_DEFINE "%define _build_id_links none")

# ── productbuild (macOS .pkg) ────────────────────────────────────────────────

set(CPACK_PRODUCTBUILD_IDENTIFIER "io.lemonade-nexus")
set(CPACK_PRODUCTBUILD_DOMAINS TRUE)
set(CPACK_PRODUCTBUILD_DOMAINS_ROOT "/usr/local")

# ── NSIS (Windows .exe installer) ───────────────────────────────────────────

set(CPACK_NSIS_DISPLAY_NAME "Lemonade-Nexus")
set(CPACK_NSIS_PACKAGE_NAME "Lemonade-Nexus")
set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
set(CPACK_NSIS_MODIFY_PATH ON)
set(CPACK_NSIS_EXECUTABLES_DIRECTORY "bin")
set(CPACK_NSIS_MUI_FINISHPAGE_RUN "lemonade-nexus.exe")

# ── Component configuration ──────────────────────────────────────────────────

# Only package our Runtime component (excludes FetchContent deps' install targets)
set(CPACK_COMPONENTS_ALL Runtime)
set(CPACK_COMPONENT_RUNTIME_DISPLAY_NAME "Lemonade-Nexus Server")
set(CPACK_COMPONENT_RUNTIME_DESCRIPTION "Lemonade-Nexus mesh VPN server daemon and service files")
set(CPACK_COMPONENT_RUNTIME_REQUIRED ON)

# DEB/RPM: don't split into per-component packages
set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_RPM_COMPONENT_INSTALL OFF)

# ── Include CPack (must be last) ─────────────────────────────────────────────

include(CPack)
