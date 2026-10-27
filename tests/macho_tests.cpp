#include <format/macho/macho_file.hpp>
#include <utils/utils.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <source_location>
#include <vector>

namespace {
using bytes_t = std::vector<std::byte>;

void check(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::cerr << "Mach-O regression check failed at line " << location.line() << "\n";
        std::exit(1);
    }
}

void number(bytes_t& data, std::uint64_t value, std::size_t size, bool big) {
    for (std::size_t i = 0; i < size; ++i) {
        const auto shift = (big ? size - i - 1 : i) * 8;
        data.push_back(static_cast<std::byte>((value >> shift) & 0xFF));
    }
}

void name(bytes_t& data, const std::string& value) {
    for (char c : value)
        data.push_back(static_cast<std::byte>(c));
    data.resize(data.size() + 16 - value.size());
}

bytes_t thin(bool is_64, bool big, std::uint32_t file_type = 2, bool zero_fill = false) {
    bytes_t data;
    const std::size_t word = is_64 ? 8 : 4;
    const std::size_t segment_size = is_64 ? 152 : 124;
    const std::size_t data_offset = (is_64 ? 32 : 28) + segment_size + 24;
    const std::size_t symbol_size = is_64 ? 16 : 12;
    auto u32 = [&](std::uint32_t value) { number(data, value, 4, big); };
    auto address = [&](std::uint64_t value) { number(data, value, word, big); };

    u32(is_64 ? 0xFEEDFACF : 0xFEEDFACE);
    u32(is_64 ? 0x0100000C : 12);
    u32(0); // cpu subtype
    u32(file_type);
    u32(2);
    u32(segment_size + 24);
    u32(0);
    if (is_64)
        u32(0);

    u32(is_64 ? 0x19 : 1);
    u32(segment_size);
    name(data, "__TEXT");
    address(0x1000);
    address(0x1000);
    address(0);
    address(data_offset + 3 + symbol_size + 6);
    u32(7);
    u32(5);
    u32(1);
    u32(0);

    name(data, "__cstring");
    name(data, "__TEXT");
    address(0x1100);
    address(3);
    u32(data_offset);
    u32(0);
    u32(0);
    u32(0);
    u32(zero_fill ? 1 : 2);
    u32(0);
    u32(0);
    if (is_64)
        u32(0);

    u32(2); // LC_SYMTAB
    u32(24);
    u32(data_offset + 3);
    u32(1);
    u32(data_offset + 3 + symbol_size);
    u32(6);
    check(data.size() == data_offset);
    data.insert(data.end(), {std::byte{'h'}, std::byte{'i'}, std::byte{0}});
    u32(1);
    number(data, 0xF, 1, big);
    number(data, 1, 1, big);
    number(data, 0x1234, 2, big);
    address(0x1100);
    for (char c : std::string("\0_sym\0", 6))
        data.push_back(static_cast<std::byte>(c));
    return data;
}

bytes_t fat(bool is_64, bool big, const bytes_t& first, const bytes_t& second) {
    bytes_t data;
    number(data, is_64 ? 0xCAFEBABF : 0xCAFEBABE, 4, big);
    number(data, 2, 4, big);
    for (std::size_t i = 0; i < 2; ++i) {
        number(data, i == 0 ? 12 : 0x0100000C, 4, big);
        number(data, 0, 4, big);
        number(data, i == 0 ? 256 : 1024, is_64 ? 8 : 4, big);
        number(data, i == 0 ? first.size() : second.size(), is_64 ? 8 : 4, big);
        number(data, 8, 4, big);
        if (is_64)
            number(data, 0, 4, big);
    }
    data.resize(256);
    data.insert(data.end(), first.begin(), first.end());
    data.resize(1024);
    data.insert(data.end(), second.begin(), second.end());
    return data;
}

void verify(const macho_file_t& file, bool is_64, bool big, std::size_t offset) {
    check(file.bitness() == (is_64 ? bitness_t::bits_64 : bitness_t::bits_32));
    check(file.endianness() == (big ? endianness_t::big : endianness_t::little));
    check(file.segments().size() == 1);
    check(file.sections().size() == 1);
    check(file.symbols().size() == 1);
    check(file.symbols()[0].name == "_sym");
    check(file.symbols()[0].address == 0x1100);
    check(file.symbols()[0].description == 0x1234);
    check(file.strings().size() == 1);
    check(file.strings()[0].value == "hi");
    check(file.strings()[0].address == 0x1100);
    check(file.segments()[0].file_offset == offset);
    check(file.strings()[0].file_offset == offset + (is_64 ? 208 : 176));
    check(file.data()[file.strings()[0].file_offset] == std::byte{'h'});
}
}

int main(int argc, char** argv) {
    std::size_t errors = 0;
    auto logger = [&](const std::string& message) {
        if (message.find("aborted") != std::string::npos)
            ++errors;
    };
    for (bool is_64 : {false, true}) {
        for (bool big : {false, true}) {
            for (auto file_type : {1u, 2u, 6u, 8u}) {
                macho_file_t file(thin(is_64, big, file_type), logger);
                verify(file, is_64, big, 0);
            }
            macho_file_t zero_fill(thin(is_64, big, 2, true), logger);
            check(zero_fill.sections().size() == 1);
            check(zero_fill.sections()[0].data.empty());
            check(zero_fill.strings().empty());

            for (bool slice_big : {false, true}) {
                auto data = fat(is_64, big, thin(false, slice_big), thin(true, !slice_big));
                macho_file_t first(data, logger);
                verify(first, false, slice_big, 256);
                check(first.slices().size() == 2);
                macho_file_t second(data, logger, nullptr, nullptr, 1);
                verify(second, true, !slice_big, 1024);
                check(second.slices().size() == 2);
            }
        }
    }
    check(errors == 0);

    auto expect_error = [&](bytes_t data, std::size_t index = 0) {
        const auto before = errors;
        macho_file_t file(std::move(data), logger, nullptr, nullptr, index);
        check(errors == before + 1);
    };
    expect_error({});
    auto data = thin(true, false);
    data.pop_back();
    expect_error(data);
    data = thin(false, true);
    data.back() = std::byte{'x'}; // unterminated symbol name
    expect_error(data);
    data = thin(true, false);
    data[36] = std::byte{8}; // segment command cannot contain its fields
    expect_error(data);
    data = fat(true, true, thin(false, false), thin(true, false));
    expect_error(data, 2);
    data[16] = std::byte{0xFF}; // 64-bit slice offset outside the file
    expect_error(data);
    data = fat(false, true, thin(false, false), thin(true, false));
    data[19] = std::byte{28}; // slice ends before its load commands
    expect_error(data);

    // Optional real-world smoke tests exercise open_binary, including fat detection.
    for (int i = 1; i < argc; ++i) {
        const auto before = errors;
        auto file = open_binary(argv[i], logger);
        check(file && !static_cast<macho_file_t&>(*file).segments().empty() && errors == before);
        const auto count = static_cast<macho_file_t&>(*file).slices().size();
        for (std::size_t index = 1; index < count; ++index) {
            auto data = utils::load_file(argv[i]);
            check(data.has_value());
            macho_file_t slice(std::move(*data), logger, nullptr, nullptr, index);
            check(!slice.segments().empty() && errors == before);
        }
    }
    std::cout << "Mach-O regression checks passed\n";
}
