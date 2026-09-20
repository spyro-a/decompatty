#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <format/binary_format.hpp>
#include <format/binary_reader.hpp>

using log_sink_t = std::function<void(const std::string&)>;

class binary_file_t {
public:
    virtual ~binary_file_t() = default;

    binary_format_t format() const noexcept { return format_; }
    cpu_type_t architecture() const noexcept { return architecture_; }
    bitness_t bitness() const noexcept { return bitness_; }
    endianness_t endianness() const noexcept { return endianness_; }

protected:
    explicit binary_file_t(std::vector<std::byte> data, log_sink_t logger = {});

    virtual void parse_header() = 0;
    virtual void analyze() = 0;

    void log(const std::string& message) {
        if (logger_)
            logger_(message);
    }

    std::vector<std::byte> data_;
    binary_reader_t reader_;

    binary_format_t format_ = binary_format_t::unknown;
    cpu_type_t architecture_ = cpu_type_t::unknown;
    bitness_t bitness_ = bitness_t::unknown;
    endianness_t endianness_ = endianness_t::unknown;

private:
    log_sink_t logger_;
};

std::unique_ptr<binary_file_t> open_binary(const char* path, log_sink_t logger = {});
