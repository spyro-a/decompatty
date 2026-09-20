#include <format/elf/elf_file.hpp>

#include <utility>

elf_file_t::elf_file_t(std::vector<std::byte> data)
    : binary_file_t(std::move(data)) {
    parse_header();
}

void elf_file_t::parse_header() {
    format_ = binary_format_t::elf;
}
