include(FetchContent)

FetchContent_Declare(
        xxhash
        GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
        GIT_TAG v0.8.3
        OVERRIDE_FIND_PACKAGE
        SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/xxhash/include/xxhash
)
FetchContent_MakeAvailable(xxhash)

add_library(xxhash INTERFACE)
target_compile_features(xxhash INTERFACE cxx_std_20)
target_include_directories(xxhash INTERFACE ${FETCHCONTENT_BASE_DIR}/xxhash/include)
