#include "format/binary_format.hpp"
#include <format/macho/macho_file.hpp>

#include <cstdio>
#include <string>
#include <utility>

namespace {
    std::string hex(std::uint32_t value) {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "%08X", value);
        return buffer;
    }
}

macho_file_t::macho_file_t(std::vector<std::byte> data, log_sink_t logger)
    : binary_file_t(std::move(data), std::move(logger)) {
    parse_header();
}

void macho_file_t::analyze() {
    
}

void macho_file_t::parse_header() {
    format_ = binary_format_t::macho;
    parse_macho(reader_.magic());
}

void macho_file_t::parse_macho(std::uint32_t magic) {
    switch (magic) {
        case FORMAT_MACHO_32_BE:
            bitness_ = bitness_t::bits_32;
            endianness_ = endianness_t::big;
            break;

        case FORMAT_MACHO_32_LE:
            bitness_ = bitness_t::bits_32;
            endianness_ = endianness_t::little;
            break;

        case FORMAT_MACHO_64_BE:
            bitness_ = bitness_t::bits_64;
            endianness_ = endianness_t::big;
            break;

        case FORMAT_MACHO_64_LE:
            bitness_ = bitness_t::bits_64;
            endianness_ = endianness_t::little;
            break;

        default:
            log("mach-o magic unknown: 0x" + hex(magic));
            return;
    }

    reader_.set_endianness(endianness_);
    reader_.seek(sizeof(std::uint32_t));

    auto cpu = reader_.u32();

    if (cpu & 0x01000000)
        cpu &= ~0x01000000;

    if (cpu & 0x02000000)
        cpu &= ~0x02000000;

    architecture_ = static_cast<cpu_type_t>(cpu);

    reader_.skip(sizeof(std::uint32_t)); // cpu subtype
    reader_.skip(sizeof(std::uint32_t)); // file type
    reader_.skip(sizeof(std::uint32_t)); // # of load commands
    reader_.skip(sizeof(std::uint32_t)); // size of load commands
    reader_.skip(sizeof(std::uint32_t)); // flags

    if (bitness_ == bitness_t::bits_64)
        reader_.skip(sizeof(std::uint32_t)); // reserved for 64-bit binaries

    log("mach-o header parsed (bitness: " + std::to_string(static_cast<int>(bitness_)) +
        ", endianness: " + std::to_string(static_cast<int>(endianness_)) + ")");
    log("cpu type: 0x" + hex(cpu));
    log("load commands begin at offset: " + std::to_string(reader_.position()));
}
