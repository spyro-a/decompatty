add_library(arch_x86_64 MODULE arch_x86_64.cpp)

set_target_properties(arch_x86_64 PROPERTIES
    PREFIX ""
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/arch
)

target_link_libraries(arch_x86_64 PRIVATE decompatty::abi)
