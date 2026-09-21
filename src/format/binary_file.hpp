#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <format/binary_format.hpp>
#include <format/binary_reader.hpp>

struct symbol_t {
    std::string name;
    std::uint64_t address;
    std::uint8_t type;
    std::uint8_t section;
    std::uint16_t description;
};

struct string_t {
    std::string value;
    std::uint64_t address;
    std::uint64_t file_offset;
};

using log_sink_t = std::function<void(const std::string&)>;

class binary_file_t {
public:
    virtual ~binary_file_t() = default;

    binary_format_t format() const noexcept { return format_; }
    cpu_type_t architecture() const noexcept { return architecture_; }
    bitness_t bitness() const noexcept { return bitness_; }
    endianness_t endianness() const noexcept { return endianness_; }

    virtual const std::vector<string_t>& strings() const = 0;
    virtual const std::vector<symbol_t>& symbols() const = 0;

    std::span<const std::byte> data() const noexcept { return data_; }
    std::size_t size() const noexcept { return data_.size(); }

protected:
    explicit binary_file_t(std::vector<std::byte> data, log_sink_t logger = {});

    virtual void parse_header() = 0;
    virtual void analyze() = 0;

    void log(const char* format, ...) const
        __attribute__((format(printf, 2, 3))) {
        if (!logger_)
            return;

        va_list args;
        va_start(args, format);

        char buffer[2048];
        std::vsnprintf(buffer, sizeof(buffer), format, args);

        va_end(args);

        logger_(buffer);
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
