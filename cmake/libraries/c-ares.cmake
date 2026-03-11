include(FetchContent)

# c-ares — MIT-licensed async DNS library with packet parsing/writing
# https://github.com/c-ares/c-ares
FetchContent_Declare(
    c-ares
    GIT_REPOSITORY https://github.com/c-ares/c-ares.git
    GIT_TAG        v1.34.6
    GIT_SHALLOW    TRUE
)

# Disable c-ares tools and tests
set(CARES_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CARES_SHARED      OFF CACHE BOOL "" FORCE)
set(CARES_STATIC      ON  CACHE BOOL "" FORCE)
set(CARES_INSTALL      OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(c-ares)
