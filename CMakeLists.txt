cmake_minimum_required(VERSION 3.22)
project(decompatty LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

add_library(decompatty_abi INTERFACE)
target_include_directories(decompatty_abi INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_library(decompatty::abi ALIAS decompatty_abi)

set(DECOMPATTY_ARCHITECTURES arm64 x86_64 CACHE STRING
    "Architectures to build loader dylibs for. Each must be a directory in src/arch/")

set(DECOMPATTY_SOURCES
    src/abi/arch_context.cpp
    src/format/binary_file.cpp
    src/format/binary_reader.cpp
    src/format/elf/elf_file.cpp
    src/format/macho/macho_file.cpp
    src/format/pe/pe_file.cpp
    src/core/app.cpp
    src/core/analysis_engine.cpp
    src/core/arch_loader.cpp
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
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(decompatty PRIVATE
    DECOMPATTY_THEME_DIR="${CMAKE_CURRENT_SOURCE_DIR}/themes"
)

target_link_libraries(decompatty PRIVATE
    Qt6::Widgets
    decompatty::abi
)

set(arch_plugins)
foreach(arch IN LISTS DECOMPATTY_ARCHITECTURES)
    add_subdirectory(src/arch/${arch} ${arch})
    list(APPEND arch_plugins arch_${arch})
endforeach()

add_dependencies(decompatty ${arch_plugins})