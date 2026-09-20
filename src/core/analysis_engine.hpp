#pragma once

#include <format/binary_file.hpp>
#include <format/binary_format.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct function_t {
    std::uint64_t address = 0;
    std::string name;
};

class analysis_engine_t {
public:
    analysis_engine_t() = default;
    analysis_engine_t(const analysis_engine_t&) = delete;
    analysis_engine_t& operator=(const analysis_engine_t&) = delete;

    bool load(const char* path);

    const binary_file_t* binary() const noexcept { return binary_.get(); }
    bool has_binary() const noexcept { return binary_ != nullptr; }

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

    const std::vector<function_t>& functions() const noexcept { return functions_; }

private:
    std::unique_ptr<binary_file_t> binary_;
    std::vector<function_t> functions_;
};