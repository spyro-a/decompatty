cmake_minimum_required(VERSION 3.22)
project(decompatty LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

set(DECOMPATTY_SOURCES
    src/format/binary_file.cpp
    src/format/binary_reader.cpp
    src/format/elf/elf_file.cpp
    src/format/macho/macho_file.cpp
    src/format/pe/pe_file.cpp
    src/core/app.cpp
    src/core/analysis_engine.cpp
    src/ui/user_interface.cpp
    src/ui/views/disassembly_view.cpp
    src/ui/views/functions_view.cpp
    src/ui/views/hex_view.cpp
    src/ui/views/output_view.cpp
    src/ui/views/strings_view.cpp
    src/utils/utils.cpp
    src/main.cpp
)

set(CMAKE_PREFIX_PATH "$ENV{HOME}/Qt/6.11.2/macos")

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(decompatty ${DECOMPATTY_SOURCES})

target_include_directories(decompatty PRIVATE
    src
)

target_compile_definitions(decompatty PRIVATE
    DECOMPATTY_THEME_DIR="${CMAKE_CURRENT_SOURCE_DIR}/themes"
)

target_link_libraries(decompatty PRIVATE
    Qt6::Widgets
)