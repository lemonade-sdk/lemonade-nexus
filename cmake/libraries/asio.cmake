include(FetchContent)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-34-2
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   FALSE
)
FetchContent_MakeAvailable(asio)

add_library(asio::asio INTERFACE IMPORTED GLOBAL)
target_include_directories(asio::asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio::asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
