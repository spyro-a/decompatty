#pragma once

#include <format/binary_file.hpp>

class elf_file_t : public binary_file_t {
public:
    explicit elf_file_t(std::vector<std::byte> data, log_sink_t logger = {});

    void analyze() override;
    
protected:
    void parse_header() override;
};
