#pragma once

#include <cstdint>

enum class cpu_type_t : std::uint32_t {
    unknown = 0x00000000,
    vax = 0x00000001,
    romp = 0x00000002,
    ns32032 = 0x00000004,
    ns32332 = 0x00000005,
    mc680x0 = 0x00000006,
    x86_64 = 0x00000007,
    mips = 0x00000008,
    ns32352 = 0x00000009,
    hp_pa = 0x0000000B,
    arm64 = 0x0000000C,
    mc88000 = 0x0000000D,
    sparc = 0x0000000E,
    i860_be = 0x0000000F,
    i860_le = 0x00000010,
    rs6000 = 0x00000011,
    power_pc = 0x00000012,
    risc_v = 0x00000018
};


enum class binary_format_t {
    unknown,
    pe,
    elf,
    macho
};

enum class bitness_t {
    unknown,
    bits_32,
    bits_64
};

enum class endianness_t {
    unknown,
    little,
    big
};

// pe
constexpr std::uint16_t FORMAT_PE = 0x4D5A;

// elf
constexpr std::uint32_t FORMAT_ELF = 0x7F454C46;

// mach-o
constexpr std::uint32_t FORMAT_MACHO_32_BE = 0xFEEDFACE;
constexpr std::uint32_t FORMAT_MACHO_32_LE = 0xCEFAEDFE;
constexpr std::uint32_t FORMAT_MACHO_64_BE = 0xFEEDFACF;
constexpr std::uint32_t FORMAT_MACHO_64_LE = 0xCFFAEDFE;

// mach-o universal / fat
constexpr std::uint32_t FORMAT_MACHO_FAT_32_BE = 0xCAFEBABE;
constexpr std::uint32_t FORMAT_MACHO_FAT_32_LE = 0xBEBAFECA;
constexpr std::uint32_t FORMAT_MACHO_FAT_64_BE = 0xCAFEBABF;
constexpr std::uint32_t FORMAT_MACHO_FAT_64_LE = 0xBFBAFECA;