include(FetchContent)

# c-ares — MIT-licensed async DNS library with packet parsing/writing
# https://github.com/c-ares/c-ares
FetchContent_Declare(
    c-ares
    GIT_REPOSITORY https://github.com/c-ares/c-ares.git
    GIT_TAG        3ac47ee46edd8ea40370222f91613fc16c434853  # v1.34.6
)

# Disable c-ares tools and tests
set(CARES_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CARES_SHARED      OFF CACHE BOOL "" FORCE)
set(CARES_STATIC      ON  CACHE BOOL "" FORCE)
set(CARES_INSTALL      OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(c-ares)
