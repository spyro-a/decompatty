#include <format/binary_file.hpp>

#include <format/elf/elf_file.hpp>
#include <format/macho/macho_file.hpp>
#include <format/pe/pe_file.hpp>

#include <utils/utils.hpp>

#include <utility>

binary_file_t::binary_file_t(std::vector<std::byte> data)
    : data_(std::move(data)),
      reader_(data_) {}

std::unique_ptr<binary_file_t> open_binary(const char* path) {
    auto data = utils::load_file(path);

    if (!data || data->size() < sizeof(std::uint32_t)) // magic is usually 4 bytes
        return nullptr;

    binary_reader_t reader(*data);
    const auto magic = reader.magic();

    switch (magic) {
        case FORMAT_ELF:
            return std::make_unique<elf_file_t>(std::move(*data));

        case FORMAT_MACHO_32_BE:
        case FORMAT_MACHO_32_LE:
        case FORMAT_MACHO_64_BE:
        case FORMAT_MACHO_64_LE:
        case FORMAT_MACHO_FAT_BE:
        case FORMAT_MACHO_FAT_LE:
            return std::make_unique<macho_file_t>(std::move(*data));

        default:
            break;
    }

    if (static_cast<std::uint16_t>(magic >> 16) == FORMAT_PE)
        return std::make_unique<pe_file_t>(std::move(*data));

    return nullptr;
}
