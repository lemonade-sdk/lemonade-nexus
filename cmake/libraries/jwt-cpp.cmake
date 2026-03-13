include(FetchContent)

FetchContent_Declare(
        jwt-cpp
        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
        GIT_TAG v0.7.0
)
# Use EXCLUDE_FROM_ALL to prevent jwt-cpp's install() targets from polluting packages.
# FetchContent_MakeAvailable doesn't support EXCLUDE_FROM_ALL until CMake 3.28,
# so we use the manual Populate + add_subdirectory approach (suppress CMP0169 warning).
cmake_policy(GET CMP0169 _cmp0169)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
FetchContent_GetProperties(jwt-cpp)
if(NOT jwt-cpp_POPULATED)
    FetchContent_Populate(jwt-cpp)
    add_subdirectory(${jwt-cpp_SOURCE_DIR} ${jwt-cpp_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
if(_cmp0169)
    cmake_policy(SET CMP0169 ${_cmp0169})
endif()
