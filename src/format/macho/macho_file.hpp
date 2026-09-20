#pragma once

#include <format/binary_file.hpp>

class macho_file_t : public binary_file_t {
public:
    explicit macho_file_t(std::vector<std::byte> data, log_sink_t logger = {});
    
    void analyze() override;
    
private:
    void parse_header() override;
    void parse_macho(std::uint32_t magic);
};
