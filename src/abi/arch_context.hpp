#pragma once

#include <abi/decompatty_arch.h>

#include <cstddef>
#include <cstdint>

class arch_context_t {
public:
    using log_fn_t = void (*)(void* ctx, const char* msg);

    arch_context_t(const decompatty_arch_api* api, log_fn_t log, void* log_ctx);
    ~arch_context_t();

    arch_context_t(const arch_context_t&) = delete;
    arch_context_t& operator=(const arch_context_t&) = delete;

    bool valid() const noexcept { return context_ != nullptr; }

    decompatty_status disassemble(const decompatty_section& section);
    std::size_t count() const noexcept;
    const decompatty_instruction* at(std::size_t index) const noexcept;
    const char* string(std::uint32_t offset) const noexcept;

private:
    const decompatty_arch_api* api_;
    decompatty_host host_;
    void* context_ = nullptr;
};
