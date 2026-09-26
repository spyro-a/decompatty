#pragma once

#include <format/binary_file.hpp>
#include <format/binary_format.hpp>

#include <core/arch_loader.hpp>

#include <memory>
#include <string>

class analysis_engine_t {
public:
    analysis_engine_t() = default;
    analysis_engine_t(const analysis_engine_t&) = delete;
    analysis_engine_t& operator=(const analysis_engine_t&) = delete;

    bool load(const char* path);

    void set_logger(log_sink_t logger) noexcept {
        logger_ = std::move(logger);
        arch_.set_logger(logger_);
    }

    void discover_archs(const std::string& dir);

    const log_sink_t& logger() const noexcept { return logger_; }
    const binary_file_t* binary() const noexcept { return binary_.get(); }
    bool has_binary() const noexcept { return binary_ != nullptr; }

    arch_loader_t& arch_loader() noexcept { return arch_; }
    const arch_loader_t& arch_loader() const noexcept { return arch_; }

    binary_format_t format() const noexcept {
        return binary_ ? binary_->format() : binary_format_t::unknown;
    }
    cpu_type_t architecture() const noexcept {
        return binary_ ? binary_->architecture() : cpu_type_t::unknown;
    }
    bitness_t bitness() const noexcept {
        return binary_ ? binary_->bitness() : bitness_t::unknown;
    }
    endianness_t endianness() const noexcept {
        return binary_ ? binary_->endianness() : endianness_t::unknown;
    }

private:
    // std::unique_ptr<disassembler_t> disassembler_;
    std::unique_ptr<binary_file_t> binary_;
    log_sink_t logger_;
    arch_loader_t arch_;
};