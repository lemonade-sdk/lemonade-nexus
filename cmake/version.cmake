# =============================================================================
# Version identity — NEXUS_VERSION, NEXUS_GIT_COMMIT, NEXUS_API_VERSION
# =============================================================================
# Precedence: -D override → git metadata → VERSION file. Overrides let a parent
# project (Lemonade) or release CI pin exact values for reproducible builds.

# Release CI already passes GIT_TAG_OVERRIDE (see packaging.cmake); reuse it
if(GIT_TAG_OVERRIDE AND NOT NEXUS_VERSION_OVERRIDE)
    set(NEXUS_VERSION_OVERRIDE "${GIT_TAG_OVERRIDE}")
endif()

find_package(Git QUIET)

if(NEXUS_VERSION_OVERRIDE)
    set(NEXUS_VERSION "${NEXUS_VERSION_OVERRIDE}")
else()
    if(Git_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
            OUTPUT_VARIABLE NEXUS_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
    endif()
    if(NOT NEXUS_VERSION)
        set(NEXUS_VERSION "${PROJECT_VERSION}")
    endif()
endif()
string(REGEX REPLACE "^v" "" NEXUS_VERSION "${NEXUS_VERSION}")

if(NEXUS_GIT_COMMIT_OVERRIDE)
    set(NEXUS_GIT_COMMIT "${NEXUS_GIT_COMMIT_OVERRIDE}")
else()
    if(Git_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
            OUTPUT_VARIABLE NEXUS_GIT_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
    endif()
    if(NOT NEXUS_GIT_COMMIT)
        set(NEXUS_GIT_COMMIT "unknown")
    endif()
endif()

# Re-run configure when the version inputs change
set_property(DIRECTORY "${PROJECT_SOURCE_DIR}" APPEND PROPERTY
    CMAKE_CONFIGURE_DEPENDS VERSION API_VERSION)

# Sidecar-facing HTTP API version — bump only on incompatible changes
file(STRINGS "${PROJECT_SOURCE_DIR}/API_VERSION" NEXUS_API_VERSION LIMIT_COUNT 1)
if(NOT NEXUS_API_VERSION MATCHES "^[0-9]+$")
    message(FATAL_ERROR "API_VERSION must be a single integer, got '${NEXUS_API_VERSION}'")
endif()

message(STATUS "lemonade-nexus ${NEXUS_VERSION} (${NEXUS_GIT_COMMIT}), sidecar API v${NEXUS_API_VERSION}")
