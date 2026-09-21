#include "format/binary_reader.hpp"
#include <format/macho/macho_file.hpp>

#include <cstdio>
#include <exception>
#include <string>
#include <utility>

macho_file_t::macho_file_t(std::vector<std::byte> data, log_sink_t logger)
    : binary_file_t(std::move(data), std::move(logger)) {
    try {
        parse_header();
    } catch (const std::exception& error) {
        log("mach-o parse aborted: %s", error.what());
    }
}

void macho_file_t::analyze() {
    
}

void macho_file_t::parse_header() {
    format_ = binary_format_t::macho;
    log("Mach-O binary detected");
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
            log("Mach-O magic unknown: 0x%08X", magic);
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
    std::uint32_t load_command_count = reader_.u32();
    std::uint32_t load_command_size = reader_.u32();
    reader_.skip(sizeof(std::uint32_t)); // flags

    if (bitness_ == bitness_t::bits_64)
        reader_.skip(sizeof(std::uint32_t)); // reserved for 64-bit binaries

    const std::size_t load_commands_begin = reader_.tell();
    const std::size_t load_commands_end = load_commands_begin + load_command_size;

    for (std::uint32_t i = 0; i < load_command_count; i++) {
        const auto start = reader_.tell();

        if (start + sizeof(macho_load_command_t) > load_commands_end) {
            log("load command %u runs past the load command region", i);
            return;
        }

        macho_load_command_t cmd;
        cmd.type = static_cast<load_command_type_t>(reader_.u32());
        cmd.size = reader_.u32();

        const bool necessary_to_run = static_cast<std::uint32_t>(cmd.type) & req_dyld_mask;

        if (cmd.size < sizeof(macho_load_command_t) || start + cmd.size > load_commands_end) {
            log("invalid load command size 0x%08X at offset 0x%zx", cmd.size, start);
            return;
        }

        // handle each command here
        switch (cmd.type) {
            // provides segments + sections
            case load_command_type_t::segment_64:
                parse_segment_64();
                break;

            // symbol table, size == 24
            case load_command_type_t::sym_tab:
                parse_symtab();
                break;

            default:
                break;
        }

        reader_.seek(start + cmd.size);
    }
}

void macho_file_t::parse_segment_64() {
    segment_command_64_t segment;
    segment.segment_name = reader_.string(16);
    segment.address = reader_.u64();
    segment.address_size = reader_.u64();
    segment.file_offset = reader_.u64();
    segment.file_size = reader_.u64();
    segment.max_protections = reader_.u32();
    segment.initial_protections = reader_.u32();
    segment.section_count = reader_.u32();
    segment.flags = reader_.u32();

    log("%s: %u sections:", segment.segment_name.c_str(), segment.section_count);
    
    segments_.push_back(std::move(segment));

    for (std::uint32_t i = 0; i < segment.section_count; ++i) {
        parse_section_64(segment);
    }
}

void macho_file_t::parse_section_64(segment_command_64_t& segment) {
    segment_section_64_t section;
    section.section_name = reader_.string(16);
    section.segment_name = reader_.string(16);
    section.address = reader_.u64();
    section.size = reader_.u64();
    section.file_offset = reader_.u32();
    section.alignment = reader_.u32();
    section.relocation_offset = reader_.u32();
    section.relocation_count = reader_.u32();
    section.flags = reader_.u32();
    section.reserved1 = reader_.u32();
    section.reserved2 = reader_.u32();
    section.reserved3 = reader_.u32();

    if (section.file_offset != 0 && section.size != 0)
        section.data = reader_.read_at(section.file_offset, section.size);

    if (section.section_name == "__cstring")
        parse_cstrings(section);

    log("  %s: 0x%llx", section.section_name.c_str(), section.address);
    
    sections_.push_back(std::move(section));
}

void macho_file_t::parse_cstrings(segment_section_64_t& section) {
    std::size_t start = 0;

    for (std::size_t i = 0; i < section.data.size(); ++i) {
        if (section.data[i] != std::byte{0})
            continue;

        if (i > start) {
            string_t string;

            string.value = std::string(reinterpret_cast<const char*>(section.data.data() + start), i - start);

            string.address = section.address + start;
            string.file_offset = section.file_offset + start;

            strings_.push_back(std::move(string));
        }

        start = i + 1;
    }
}

void macho_file_t::parse_symtab() {
    symbol_table_command_t table;
    table.symbols_offset = reader_.u32();
    table.symbol_count = reader_.u32();
    table.strings_offset = reader_.u32();
    table.strings_size = reader_.u32();

    log("%u symbols, %u string bytes", table.symbol_count, table.strings_size);

     // we are at the start of the next LOAD command
    const auto command_end = reader_.tell();

    // jump to string table
    reader_.seek(table.strings_offset);
    const auto string_table = reader_.bytes(table.strings_size);

    // read symbols
    reader_.seek(table.symbols_offset);

    for (std::uint32_t i = 0; i < table.symbol_count; ++i) {
        symbol_t symbol;

        std::uint32_t string_index = reader_.u32();
        symbol.type = reader_.u8();
        symbol.section = reader_.u8();
        symbol.description = reader_.u16();
        symbol.address = reader_.u64();

        if (string_index >= string_table.size())
            continue;

        const char* str = reinterpret_cast<const char*>(string_table.data() + string_index);
        symbol.name = str;

        symbols_.push_back(std::move(symbol));
    }
    
    // jump back to start of the next LOAD command
    reader_.seek(command_end);
}