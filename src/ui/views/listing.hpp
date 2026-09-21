#pragma once

#include <cstdint>
#include <string>

struct listing_line_t {
    std::uint64_t address = 0;
    std::string label;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    std::string comment;
};