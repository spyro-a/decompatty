#pragma once

#include <abi/arch_context.hpp>
#include <abi/decompatty_arch.h>

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <filesystem>
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

struct instruction_t {
    std::uint64_t address;
    std::string mnemonic;
    std::string operands;
    std::uint64_t file_offset;
    std::uint8_t length;
    std::uint8_t flags;
};

using log_sink_t = std::function<void(const std::string&)>;

using arch_resolver_t = const decompatty_arch_api* (*)(void* ctx, std::uint32_t cpu, std::uint32_t format);

class binary_file_t {
public:
    virtual ~binary_file_t() = default;

    binary_format_t format() const noexcept { return format_; }
    cpu_type_t architecture() const noexcept { return architecture_; }
    bitness_t bitness() const noexcept { return bitness_; }
    endianness_t endianness() const noexcept { return endianness_; }

    virtual const std::vector<string_t>& strings() const = 0;
    virtual const std::vector<symbol_t>& symbols() const = 0;

    virtual const std::vector<instruction_t>& instructions() const {
        static const std::vector<instruction_t> none;
        return none;
    }

    std::span<const std::byte> data() const noexcept { return data_; }
    std::size_t size() const noexcept { return data_.size(); }

    std::uint64_t entry_point() const noexcept {
        return entry_point_;
    }

    std::uint64_t stack_size() const noexcept {
        return stack_size_;
    }

    std::uint64_t image_base() const noexcept {
        return image_base_;
    }

    std::uint64_t image_end() const noexcept {
        return image_end_;
    }

protected:
    explicit binary_file_t(std::vector<std::byte> data, log_sink_t logger = {},
                           arch_resolver_t resolver = nullptr, void* resolver_ctx = nullptr);

    virtual void parse_header() = 0;

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

    const log_sink_t& logger() const noexcept { return logger_; }

    static void arch_log_trampoline(void* ctx, const char* msg) {
        const auto* self = static_cast<const binary_file_t*>(ctx);
        self->logger()(std::string(msg));
    }

    bool ensure_arch() {
        if (arch_)
            return arch_->valid();

        if (!resolver_)
            return false;

        const decompatty_arch_api* api = resolver_(resolver_ctx_,
                                                    static_cast<std::uint32_t>(architecture_),
                                                    static_cast<std::uint32_t>(format_));
        if (!api)
            return false;

        arch_ = std::make_unique<arch_context_t>(api, arch_log_trampoline, this);
        return arch_->valid();
    }

    std::vector<std::byte> data_;
    binary_reader_t reader_;

    std::uint64_t entry_point_ = 0;
    std::uint64_t stack_size_ = 0;

    std::uint64_t image_base_ = UINT64_MAX;
    std::uint64_t image_end_ = 0;

    binary_format_t format_ = binary_format_t::unknown;
    cpu_type_t architecture_ = cpu_type_t::unknown;
    bitness_t bitness_ = bitness_t::unknown;
    endianness_t endianness_ = endianness_t::unknown;

    std::unique_ptr<arch_context_t> arch_;

private:
    log_sink_t logger_;
    arch_resolver_t resolver_ = nullptr;
    void* resolver_ctx_ = nullptr;
};

std::unique_ptr<binary_file_t> open_binary(const char* path, log_sink_t logger = {},
                                           arch_resolver_t resolver = nullptr,
                                           void* resolver_ctx = nullptr);
