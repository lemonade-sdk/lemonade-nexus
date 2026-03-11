include(FetchContent)

FetchContent_Declare(
        jwt-cpp
        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
        GIT_TAG v0.7.0
)
# Use EXCLUDE_FROM_ALL to prevent jwt-cpp's install() targets from polluting packages
FetchContent_GetProperties(jwt-cpp)
if(NOT jwt-cpp_POPULATED)
    FetchContent_Populate(jwt-cpp)
    add_subdirectory(${jwt-cpp_SOURCE_DIR} ${jwt-cpp_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
