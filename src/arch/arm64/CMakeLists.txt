add_library(arch_arm64 MODULE arch_arm64.cpp arm64_decode.cpp)

set_target_properties(arch_arm64 PROPERTIES
    PREFIX ""
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/arch
)

target_include_directories(arch_arm64 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(arch_arm64 PRIVATE decompatty::abi)
