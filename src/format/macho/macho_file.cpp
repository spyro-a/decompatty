#include <format/macho/macho_file.hpp>

#include <utility>

macho_file_t::macho_file_t(std::vector<std::byte> data)
    : binary_file_t(std::move(data)) {
    parse_header();
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
}
