#pragma once

#include <cstdint>
#include <string>

struct arm64_instruction_t {
    std::uint32_t bits = 0;
    std::uint8_t length = 4;
    std::string mnemonic;
    std::string operands;
    bool branch = false;
};

bool arm64_decode(std::uint32_t bits, std::uint64_t address, arm64_instruction_t& out);