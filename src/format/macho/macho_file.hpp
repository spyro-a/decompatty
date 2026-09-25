#pragma once

#include <format/binary_file.hpp>

#include <cstdint>

enum class load_command_type_t : uint32_t {
    segment                   = 0x00000001, // LC_SEGMENT
    sym_tab                   = 0x00000002, // LC_SYMTAB
    sym_seg                   = 0x00000003, // LC_SYMSEG
    thread                    = 0x00000004, // LC_THREAD
    unix_thread               = 0x00000005, // LC_UNIXTHREAD
    load_fvm_lib              = 0x00000006, // LC_LOADFVMLIB
    id_fvm_lib                = 0x00000007, // LC_IDFVMLIB
    ident                     = 0x00000008, // LC_IDENT
    fvm_file                  = 0x00000009, // LC_FVMFILE
    pre_page                  = 0x0000000A, // LC_PREPAGE
    dy_sym_tab                = 0x0000000B, // LC_DYSYMTAB
    load_dylib                = 0x0000000C, // LC_LOAD_DYLIB
    id_dylib                  = 0x0000000D, // LC_ID_DYLIB
    load_dylinker             = 0x0000000E, // LC_LOAD_DYLINKER
    id_dylinker               = 0x0000000F, // LC_ID_DYLINKER
    prebound_dylib            = 0x00000010, // LC_PREBOUND_DYLIB
    routines                  = 0x00000011, // LC_ROUTINES
    sub_framework             = 0x00000012, // LC_SUB_FRAMEWORK
    sub_umbrella              = 0x00000013, // LC_SUB_UMBRELLA
    sub_client                = 0x00000014, // LC_SUB_CLIENT
    sub_library               = 0x00000015, // LC_SUB_LIBRARY
    two_level_hints           = 0x00000016, // LC_TWOLEVEL_HINTS
    prebind_cksum             = 0x00000017, // LC_PREBIND_CKSUM

    // 64-bit and modern formats
    load_weak_dylib           = 0x80000018, // LC_LOAD_WEAK_DYLIB
    segment_64                = 0x00000019, // LC_SEGMENT_64
    routines_64               = 0x0000001A, // LC_ROUTINES_64
    uuid                      = 0x0000001B, // LC_UUID
    rpath                     = 0x8000001C, // LC_RPATH
    code_signature            = 0x0000001D, // LC_CODE_SIGNATURE
    segment_split_info        = 0x0000001E, // LC_SEGMENT_SPLIT_INFO
    reexport_dylib            = 0x8000001F, // LC_REEXPORT_DYLIB
    lazy_load_dylib           = 0x00000020, // LC_LAZY_LOAD_DYLIB
    encryption_info           = 0x00000021, // LC_ENCRYPTION_INFO
    dyld_info                 = 0x00000022, // LC_DYLD_INFO
    dyld_info_only            = 0x80000022, // LC_DYLD_INFO_ONLY
    load_upward_dylib         = 0x80000023, // LC_LOAD_UPWARD_DYLIB
    version_min_macos         = 0x00000024, // LC_VERSION_MIN_MACOSX
    version_min_ios           = 0x00000025, // LC_VERSION_MIN_IPHONEOS
    function_starts           = 0x00000026, // LC_FUNCTION_STARTS
    dyld_environment          = 0x00000027, // LC_DYLD_ENVIRONMENT
    main                      = 0x80000028, // LC_MAIN
    data_in_code              = 0x00000029, // LC_DATA_IN_CODE
    source_version            = 0x0000002A, // LC_SOURCE_VERSION
    dylib_code_sign_drs       = 0x0000002B, // LC_DYLIB_CODE_SIGN_DRS
    encryption_info_64        = 0x0000002C, // LC_ENCRYPTION_INFO_64
    linker_option             = 0x0000002D, // LC_LINKER_OPTION
    linker_optimization_hint  = 0x0000002E, // LC_LINKER_OPTIMIZATION_HINT
    version_min_tvos          = 0x0000002F, // LC_VERSION_MIN_TVOS
    version_min_watchos       = 0x00000030, // LC_VERSION_MIN_WATCHOS
    note                      = 0x00000031, // LC_NOTE
    build_version             = 0x00000032, // LC_BUILD_VERSION
    dyld_exports_trie         = 0x80000033, // LC_DYLD_EXPORTS_TRIE
    dyld_chained_fixups       = 0x80000034, // LC_DYLD_CHAINED_FIXUPS
    fileset_entry             = 0x80000035  // LC_FILESET_ENTRY
};

inline constexpr uint32_t req_dyld_mask = 0x80000000; // necessary to run binary or not

struct macho_load_command_t {
    load_command_type_t type;
    std::uint32_t size;
};

struct segment_command_64_t {
    std::string segment_name; // 16 bytes
    uint64_t address;
    uint64_t address_size;
    uint64_t file_offset;
    uint64_t file_size;
    uint32_t max_protections;
    uint32_t initial_protections;
    uint32_t section_count;
    uint32_t flags;
};

struct segment_section_64_t {
    std::string section_name;
    std::string segment_name;
    std::uint64_t address;
    std::uint64_t size;
    std::uint32_t file_offset;
    std::uint32_t alignment;
    std::uint32_t relocation_offset;
    std::uint32_t relocation_count;
    std::uint32_t flags;
    std::uint32_t reserved1;
    std::uint32_t reserved2;
    std::uint32_t reserved3;

    std::span<const std::byte> data;
};

struct symbol_table_command_t {
    std::uint32_t symbols_offset;
    std::uint32_t symbol_count;
    std::uint32_t strings_offset;
    std::uint32_t strings_size;
};

class macho_file_t : public binary_file_t {
public:
    explicit macho_file_t(std::vector<std::byte> data, log_sink_t logger = {});

    const std::vector<segment_command_64_t>& segments() const {
        return segments_;
    }

    const std::vector<segment_section_64_t>& sections() const {
        return sections_;
    }

    const std::vector<symbol_t>& symbols() const override {
        return symbols_;
    }

    const std::vector<string_t>& strings() const override {
        return strings_;
    }

private:
    std::uint32_t load_command_count = 0;
    std::uint32_t load_command_size = 0;
    std::size_t load_commands_begin = 0;
    std::size_t load_commands_end = 0;

    std::vector<segment_command_64_t> segments_;
    std::vector<segment_section_64_t> sections_;

    std::vector<symbol_t> symbols_;
    std::vector<string_t> strings_;

    void parse_header() override;
    void parse_macho();
    void parse_macho_fat(std::uint32_t magic);

    // LOAD command parsers
    void parse_segment_64();
    void parse_section_64(segment_command_64_t& segment);
    void parse_cstrings(segment_section_64_t& section);
    void parse_text(segment_section_64_t& section);

    void parse_symtab();
};
