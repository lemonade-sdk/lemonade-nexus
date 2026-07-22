include(FetchContent)

FetchContent_Declare(
        magic_enum
        GIT_REPOSITORY https://github.com/Neargye/magic_enum.git
        GIT_TAG e046b69a3736d314fad813e159b1c192eaef92cd  # v0.9.7
        OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(magic_enum)
