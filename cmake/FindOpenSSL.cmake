# =============================================================================
# Custom FindOpenSSL.cmake — short-circuit for project-built OpenSSL
# =============================================================================
# This file lives in ${PROJECT_SOURCE_DIR}/cmake/ which is on CMAKE_MODULE_PATH,
# so it takes precedence over CMake's built-in FindOpenSSL.cmake.
#
# When cmake/libraries/openssl.cmake has already defined the OpenSSL::SSL and
# OpenSSL::Crypto IMPORTED targets (via ExternalProject_Add), we skip all
# search logic and simply report success.  This prevents httplib, jwt-cpp, and
# other FetchContent dependencies from picking up Homebrew or system OpenSSL.
# =============================================================================

if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
    # Targets already exist — set the standard result variables so
    # find_package_handle_standard_args and downstream checks are happy.
    set(OpenSSL_FOUND TRUE)
    set(OPENSSL_FOUND TRUE)

    # Component handling — mark all requested components as found.
    foreach(_comp IN LISTS OpenSSL_FIND_COMPONENTS)
        set(OpenSSL_${_comp}_FOUND TRUE)
    endforeach()

    # Populate aggregate variables that some projects check directly.
    set(OPENSSL_LIBRARIES    "${OPENSSL_SSL_LIBRARY};${OPENSSL_CRYPTO_LIBRARY}")
    set(OPENSSL_SSL_LIBRARIES    "${OPENSSL_SSL_LIBRARY}")
    set(OPENSSL_CRYPTO_LIBRARIES "${OPENSSL_CRYPTO_LIBRARY}")

    if(NOT OpenSSL_FIND_QUIETLY)
        message(STATUS "FindOpenSSL: using project-built OpenSSL ${OPENSSL_VERSION} (targets already defined)")
    endif()
    return()
endif()

# If we get here, openssl.cmake hasn't run yet (shouldn't happen in normal builds).
# Fall through to CMake's built-in FindOpenSSL by including it directly.
include(${CMAKE_ROOT}/Modules/FindOpenSSL.cmake)
