find_package(LLVM REQUIRED CONFIG HINTS
    /opt/homebrew/opt/llvm/lib/cmake/llvm
    /usr/local/opt/llvm/lib/cmake/llvm
)

add_library(arch_x86_64 MODULE arch_x86_64.cpp)

set_target_properties(arch_x86_64 PROPERTIES
    PREFIX ""
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/arch
)

target_link_libraries(arch_x86_64 PRIVATE decompatty::abi)

target_include_directories(arch_x86_64 SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
if(TARGET LLVM)
    target_link_libraries(arch_x86_64 PRIVATE LLVM)
else()
    llvm_map_components_to_libnames(x86_disassembler_libs X86Disassembler X86Desc X86Info MCDisassembler)
    target_link_libraries(arch_x86_64 PRIVATE ${x86_disassembler_libs})
endif()
