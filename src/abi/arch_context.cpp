#include <abi/arch_context.hpp>

arch_context_t::arch_context_t(const decompatty_arch_api* api, log_fn_t log, void* log_ctx)
    : api_(api) {
    if (!api_)
        return;

    host_.struct_size = sizeof(host_);
    host_.abi_version = DECOMPATTY_ABI_VERSION;
    host_.log = log;
    host_.log_context = log_ctx;

    if (api_->create(&host_, &context_) != DECOMPATTY_OK)
        context_ = nullptr;
}

arch_context_t::~arch_context_t() {
    if (context_ && api_)
        api_->destroy(context_);
}

decompatty_status arch_context_t::disassemble(const decompatty_section& section) {
    if (!context_)
        return DECOMPATTY_ERR_INVAL;
    return api_->disassemble(context_, &section, &host_);
}

std::size_t arch_context_t::count() const noexcept {
    return context_ ? api_->instruction_count(context_) : 0;
}

const decompatty_instruction* arch_context_t::at(std::size_t index) const noexcept {
    return context_ ? api_->instruction_at(context_, index) : nullptr;
}

const char* arch_context_t::string(std::uint32_t offset) const noexcept {
    return context_ ? api_->string_at(context_, offset) : "";
}
