#pragma once

#include <format/binary_file.hpp>

class pe_file_t : public binary_file_t {
public:
    explicit pe_file_t(std::vector<std::byte> data);

    void analyze() override;
    
private:
    void parse_header() override;
};
