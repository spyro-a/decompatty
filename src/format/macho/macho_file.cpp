#include "format/binary_format.hpp"
#include "format/binary_reader.hpp"
#include <format/macho/macho_file.hpp>

#include <algorithm>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <exception>
#include <string>
#include <utility>

macho_file_t::macho_file_t(std::vector<std::byte> data, log_sink_t logger, arch_resolver_t resolver, void* resolver_ctx, std::size_t slice_index, bool defer_disassembly)
    : binary_file_t(std::move(data), std::move(logger), resolver, resolver_ctx),
      defer_disassembly_(defer_disassembly),
      slice_index_(slice_index) {
    try {
        parse_header();
        parse_macho();
        valid_ = true;
        log("Image base: 0x%llx\nImage end: 0x%llx", image_base(), image_end());
    } catch (const std::exception& error) {
        log("Mach-o parse aborted: %s", error.what());
    }
}

void macho_file_t::parse_header() {
    format_ = binary_format_t::macho;
    log("Mach-O binary detected");
    const auto magic = reader_.magic();
    switch (magic) {
        case FORMAT_MACHO_FAT_32_BE:
        case FORMAT_MACHO_FAT_32_LE:
        case FORMAT_MACHO_FAT_64_BE:
        case FORMAT_MACHO_FAT_64_LE:
            parse_macho_fat(magic);
            return;

        default:
            break;
    }

    switch (magic) {
        case FORMAT_MACHO_64_BE:
            bitness_ = bitness_t::bits_64;
            endianness_ = endianness_t::big;
            break;

        case FORMAT_MACHO_64_LE:
            bitness_ = bitness_t::bits_64;
            endianness_ = endianness_t::little;
            break;

        case FORMAT_MACHO_32_BE:
            bitness_ = bitness_t::bits_32;
            endianness_ = endianness_t::big;
            break;

        case FORMAT_MACHO_32_LE:
            bitness_ = bitness_t::bits_32;
            endianness_ = endianness_t::little;
            break;

        default:
            throw std::runtime_error("unknown Mach-O slice magic");
    }

    reader_.seek(sizeof(magic));
    reader_.set_endianness(endianness_);

    // whatever is skipped is not something that is necessary in the current scope of the project
    architecture_ = static_cast<cpu_type_t>(reader_.u32() & ~(0x01000000 | 0x02000000));
    reader_.skip(sizeof(std::uint32_t)); // cpu subtype
    reader_.skip(sizeof(std::uint32_t)); // file type
    load_command_count = reader_.u32();
    load_command_size = reader_.u32();
    reader_.skip(sizeof(std::uint32_t)); // flags

    if (bitness_ == bitness_t::bits_64)
        reader_.skip(sizeof(std::uint32_t)); // reserved for 64-bit binaries

    load_commands_begin = reader_.tell();
    if (!reader_.can_read(load_command_size))
        throw std::out_of_range("load commands run past the Mach-O slice");

    load_commands_end = load_commands_begin + load_command_size;
}

void macho_file_t::parse_macho() {
    for (std::uint32_t i = 0; i < load_command_count; i++) {
        const auto start = reader_.tell();

        if (start + sizeof(macho_load_command_t) > load_commands_end) {
            throw std::out_of_range("load command runs past the load command region");
        }

        macho_load_command_t cmd;
        cmd.type = static_cast<load_command_type_t>(reader_.u32());
        cmd.size = reader_.u32();

        // const bool necessary_to_run = static_cast<std::uint32_t>(cmd.type) & req_dyld_mask;

        if (cmd.size < sizeof(macho_load_command_t) || start + cmd.size > load_commands_end) {
            throw std::out_of_range("invalid Mach-O load command size");
        }

        command_end_ = start + cmd.size;

        // handle load commands here
        switch (cmd.type) {
            // TODO: use this as the official entry point; computing it should be a fallback
            // case load_command_type_t::main:
            //     parse_main();
            //     break;

            // ULEB128 delta-encoded
            case load_command_type_t::function_starts:
                parse_function_start_addresses();
                break;

            // provides segments + sections
            case load_command_type_t::segment:
                if (bitness_ != bitness_t::bits_32)
                    throw std::runtime_error("32-bit segment in a 64-bit Mach-O");
                parse_segment(false);
                break;

            case load_command_type_t::segment_64:
                if (bitness_ != bitness_t::bits_64)
                    throw std::runtime_error("64-bit segment in a 32-bit Mach-O");
                parse_segment(true);
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

void macho_file_t::parse_macho_fat(std::uint32_t magic) {
    const bool is_64 = magic == FORMAT_MACHO_FAT_64_BE || magic == FORMAT_MACHO_FAT_64_LE;
    const bool is_big = magic == FORMAT_MACHO_FAT_32_BE || magic == FORMAT_MACHO_FAT_64_BE;
    reader_.set_endianness(is_big ? endianness_t::big : endianness_t::little);
    reader_.seek(sizeof(magic));

    const auto count = reader_.u32();
    const std::size_t record_size = is_64 ? 32 : 20;
    if (count == 0 || count > reader_.remaining() / record_size)
        throw std::out_of_range("invalid Mach-O fat architecture table");

    const auto table_end = reader_.tell() + count * record_size;
    for (std::uint32_t i = 0; i < count; ++i) {
        macho_slice_t slice;
        slice.cpu_type = reader_.u32();
        slice.cpu_subtype = reader_.u32();
        slice.file_offset = is_64 ? reader_.u64() : reader_.u32();
        slice.file_size = is_64 ? reader_.u64() : reader_.u32();
        slice.alignment = reader_.u32();
        if (is_64)
            reader_.skip(sizeof(std::uint32_t)); // reserved

        if (slice.file_offset < table_end || slice.file_offset > data_.size() ||
            slice.file_size < 28 || slice.file_size > data_.size() - slice.file_offset ||
            slice.alignment >= 64 || slice.file_offset % (std::uint64_t{1} << slice.alignment) != 0)
            throw std::out_of_range("invalid Mach-O fat slice range or alignment");

        slices_.push_back(slice);
    }

    if (slice_index_ >= slices_.size())
        throw std::out_of_range("Mach-O fat slice index out of range");

    const auto& slice = slices_[slice_index_];
    slice_offset_ = slice.file_offset;
    reader_ = binary_reader_t(std::span<const std::byte>(data_).subspan(slice.file_offset, slice.file_size));
    const auto slice_magic = reader_.magic();
    if (slice_magic != FORMAT_MACHO_32_BE && slice_magic != FORMAT_MACHO_32_LE &&
        slice_magic != FORMAT_MACHO_64_BE && slice_magic != FORMAT_MACHO_64_LE)
        throw std::runtime_error("fat slice is not a thin Mach-O");

    log("Mach-O fat binary: %zu slices, selecting slice %zu", slices_.size(), slice_index_);
    parse_header();
}


void macho_file_t::parse_main() {
    entry_point_command_t entry;
    entry.entry_offset = reader_.u64();
    entry.stack_size = reader_.u64();
}

void macho_file_t::parse_function_start_addresses() {
    if (command_end_ - reader_.tell() < 8)
        throw std::out_of_range("truncated Mach-O function starts command");

    function_starts_command_t function_starts;
    function_starts.data_offset = reader_.u32();
    function_starts.data_size = reader_.u32();
}

void macho_file_t::parse_segment(bool is_64) {
    const std::size_t segment_size = is_64 ? 64 : 48;
    const std::size_t section_size = is_64 ? 80 : 68;
    if (command_end_ - reader_.tell() < segment_size)
        throw std::out_of_range("truncated Mach-O segment command");

    segment_command_64_t segment;
    segment.segment_name = reader_.string(16);
    segment.address = is_64 ? reader_.u64() : reader_.u32();
    segment.address_size = is_64 ? reader_.u64() : reader_.u32();
    segment.file_offset = is_64 ? reader_.u64() : reader_.u32();
    segment.file_size = is_64 ? reader_.u64() : reader_.u32();
    segment.max_protections = reader_.u32();
    segment.initial_protections = reader_.u32();
    segment.section_count = reader_.u32();
    segment.flags = reader_.u32();

    if (segment.section_count > (command_end_ - reader_.tell()) / section_size)
        throw std::out_of_range("sections run past the Mach-O segment command");

    if (!reader_.can_read(segment.file_offset, segment.file_size) ||
        segment.address_size > std::numeric_limits<std::uint64_t>::max() - segment.address)
        throw std::out_of_range("invalid Mach-O segment range");

    segment.file_offset += slice_offset_;

    if (segment.file_size != 0 && segment.address_size != 0) {
        image_base_ = std::min(image_base_, segment.address);
        image_end_ = std::max(image_end_, segment.address + segment.address_size);
    }

    log("%s: %u sections:", segment.segment_name.c_str(), segment.section_count);
    
    for (std::uint32_t i = 0; i < segment.section_count; ++i)
        parse_section(is_64);

    segments_.push_back(std::move(segment));
}

void macho_file_t::parse_section(bool is_64) {
    segment_section_64_t section{};
    section.section_name = reader_.string(16);
    section.segment_name = reader_.string(16);
    section.address = is_64 ? reader_.u64() : reader_.u32();
    section.size = is_64 ? reader_.u64() : reader_.u32();
    section.file_offset = reader_.u32();
    section.alignment = reader_.u32();
    section.relocation_offset = reader_.u32();
    section.relocation_count = reader_.u32();
    section.flags = reader_.u32();
    section.reserved1 = reader_.u32();
    section.reserved2 = reader_.u32();
    if (is_64)
        section.reserved3 = reader_.u32();

    const auto section_type = section.flags & 0xFF;
    const bool zero_fill = section_type == 0x1 || section_type == 0xC || section_type == 0x12;
    if (!zero_fill && section.size != 0)
        section.data = reader_.read_at(section.file_offset, section.size);

    section.file_offset += slice_offset_;

    if (section.section_name == "__cstring")
        parse_cstrings(section);

    if (!defer_disassembly_ && section.section_name == "__text")
        parse_text(section);

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

void macho_file_t::parse_text(segment_section_64_t& section) {
    disassemble_section(section, [this](instruction_batch_t batch) {
        instructions_.insert(instructions_.end(), batch->begin(), batch->end());
        return true;
    }, {});
}

bool macho_file_t::disassemble(const instruction_sink_t& sink, std::stop_token stop) {
    if (!valid_ || !sink)
        return false;

    for (const auto& section : sections_) {
        if (stop.stop_requested())
            return false;
        if (section.section_name == "__text" && !disassemble_section(section, sink, stop))
            return false;
    }
    return !stop.stop_requested();
}

bool macho_file_t::disassemble_section(const segment_section_64_t& section,
                                       const instruction_sink_t& sink, std::stop_token stop) {
    if (section.data.empty())
        return true;

    if (!ensure_arch()) {
        log("no compatible architecture plugin for cpu 0x%02X", static_cast<unsigned>(architecture_));
        return false;
    }

    constexpr std::size_t chunk_size = 16384;
    constexpr std::size_t lookahead = 15; // maximum x86 instruction size
    std::size_t offset = 0;
    std::size_t total = 0;
    while (offset < section.data.size()) {
        if (stop.stop_requested())
            return false;

        const auto remaining = section.data.size() - offset;
        decompatty_section input{};
        input.data = reinterpret_cast<const std::uint8_t*>(section.data.data() + offset);
        input.length = std::min(remaining, chunk_size + lookahead);
        input.address = section.address + offset;
        input.file_offset = section.file_offset + offset;
        input.section_name = section.section_name.c_str();
        if (arch_->disassemble(input, true) != DECOMPATTY_OK)
            return false;

        auto batch = std::make_shared<std::vector<instruction_t>>();
        batch->reserve(arch_->count());
        std::size_t consumed = 0;
        for (std::size_t i = 0; i < arch_->count(); ++i) {
            const auto* raw = arch_->at(i);
            if (!raw || raw->section_offset >= chunk_size)
                break;
            if (raw->section_offset != consumed || raw->length == 0 ||
                raw->length > input.length - consumed)
                return false;

            instruction_t instruction;
            instruction.address = raw->address;
            instruction.mnemonic = arch_->string(raw->mnemonic_offset);
            instruction.operands = arch_->string(raw->operands_offset);
            instruction.file_offset = input.file_offset + raw->section_offset;
            instruction.length = raw->length;
            instruction.flags = raw->flags;
            batch->push_back(std::move(instruction));
            consumed += raw->length;
        }

        total += batch->size();
        if (consumed == 0 || stop.stop_requested() || !sink(std::move(batch)))
            return false;
        offset += consumed;
    }
    log("%s: %zu instructions decoded", section.section_name.c_str(), total);
    return true;
}

void macho_file_t::parse_symtab() {
    if (command_end_ - reader_.tell() < 16)
        throw std::out_of_range("truncated Mach-O symbol table command");
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
    const std::size_t symbol_size = bitness_ == bitness_t::bits_64 ? 16 : 12;
    const auto slice_size = reader_.tell() + reader_.remaining();
    if (table.symbols_offset > slice_size ||
        table.symbol_count > (slice_size - table.symbols_offset) / symbol_size)
        throw std::out_of_range("symbols run past the Mach-O slice");

    reader_.seek(table.symbols_offset);

    for (std::uint32_t i = 0; i < table.symbol_count; ++i) {
        symbol_t symbol;

        std::uint32_t string_index = reader_.u32();
        symbol.type = reader_.u8();
        symbol.section = reader_.u8();
        symbol.description = reader_.u16();
        symbol.address = bitness_ == bitness_t::bits_64 ? reader_.u64() : reader_.u32();

        if (string_index >= string_table.size())
            continue;

        const char* str = reinterpret_cast<const char*>(string_table.data() + string_index);
        const auto length = string_table.size() - string_index;
        const auto end = std::find(str, str + length, '\0');
        if (end == str + length)
            throw std::runtime_error("unterminated Mach-O symbol name");

        symbol.name.assign(str, end);

        symbols_.push_back(std::move(symbol));
    }
    
    // jump back to start of the next LOAD command
    reader_.seek(command_end);
}