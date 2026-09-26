#pragma once

#include <abi/decompatty_arch.h>
#include <format/binary_file.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

class arch_loader_t {
public:
    arch_loader_t() = default;
    arch_loader_t(const arch_loader_t&) = delete;
    arch_loader_t& operator=(const arch_loader_t&) = delete;
    ~arch_loader_t() = default;

    void set_logger(log_sink_t logger) noexcept { logger_ = std::move(logger); }

    void discover(const std::string& dir);
    const decompatty_arch_api* find(std::uint32_t cpu, std::uint32_t format) const;

    std::size_t size() const noexcept { return plugins_.size(); }

    const decompatty_arch_api* at(std::size_t i) const noexcept {
        return i < plugins_.size() ? plugins_[i].api : nullptr;
    }

private:
    struct plugin_t {
        void* handle;
        const decompatty_arch_api* api;
    };

    void log(const char* format, ...) const
        __attribute__((format(printf, 2, 3)));

    std::vector<plugin_t> plugins_;
    log_sink_t logger_;
};
