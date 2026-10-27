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
add_executable(macho_tests EXCLUDE_FROM_ALL
    tests/macho_tests.cpp
    src/abi/arch_context.cpp
    src/format/binary_file.cpp
    src/format/binary_reader.cpp
    src/format/macho/macho_file.cpp
    src/utils/utils.cpp
)
target_include_directories(macho_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(macho_tests PRIVATE Qt6::Core)

add_executable(disassembly_tests EXCLUDE_FROM_ALL
    tests/disassembly_tests.cpp
    src/ui/views/strings_view.cpp
    src/abi/arch_context.cpp
    src/format/binary_file.cpp
    src/format/binary_reader.cpp
    src/format/macho/macho_file.cpp
    src/utils/utils.cpp
)
target_include_directories(disassembly_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(disassembly_tests PRIVATE Qt6::Widgets ${CMAKE_DL_LIBS})
if(TARGET arch_x86_64)
    add_dependencies(disassembly_tests arch_x86_64)
endif()

set(ASYNC_TEST_SOURCES ${DECOMPATTY_SOURCES})
list(REMOVE_ITEM ASYNC_TEST_SOURCES src/main.cpp)
add_executable(async_tests EXCLUDE_FROM_ALL tests/async_tests.cpp ${ASYNC_TEST_SOURCES})
target_include_directories(async_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(async_tests PRIVATE Qt6::Widgets ${CMAKE_DL_LIBS})
add_dependencies(async_tests ${arch_plugins})
