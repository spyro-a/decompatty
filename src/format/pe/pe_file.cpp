#include <format/pe/pe_file.hpp>

#include <utility>

pe_file_t::pe_file_t(std::vector<std::byte> data, log_sink_t logger)
    : binary_file_t(std::move(data), std::move(logger)) {
    parse_header();
}

void pe_file_t::analyze() {
    
}

void pe_file_t::parse_header() {
    format_ = binary_format_t::pe;
}
