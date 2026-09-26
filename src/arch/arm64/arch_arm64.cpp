#include <abi/decompatty_arch.h>

#include <cstddef>
#include <cstring>
#include <new>

struct arm64_context_t {
    char pool[4096];
    std::size_t pool_used = 0;
    const decompatty_instruction* instructions = nullptr;
    std::size_t count = 0;
    const char* name = "arm64";
};

void log_to_host(const decompatty_host* host, const char* msg) {
    if (host && host->log)
        host->log(host->log_context, msg);
}

const char* intern(arm64_context_t* ctx, const char* text) {
    const std::size_t len = std::strlen(text) + 1;
    if (ctx->pool_used + len > sizeof(ctx->pool))
        return "";

    char* slot = ctx->pool + ctx->pool_used;
    std::memcpy(slot, text, len);
    ctx->pool_used += len;
    return slot;
}

decompatty_status create(const decompatty_host* host, void** out_context) {
    if (!out_context)
        return DECOMPATTY_ERR_INVAL;

    auto* ctx = new (std::nothrow) arm64_context_t();
    if (!ctx)
        return DECOMPATTY_ERR_NOMEM;

    *out_context = ctx;
    log_to_host(host, "arm64: decoder instance created");
    return DECOMPATTY_OK;
}

void destroy(void* context) {
    delete static_cast<arm64_context_t*>(context);
}

decompatty_status disassemble(void* context, const decompatty_section* section, const decompatty_host* host) {
    if (!context || !section || !section->data)
        return DECOMPATTY_ERR_INVAL;

    log_to_host(host, "arm64: no decoder linked, cannot decode __text");
    return DECOMPATTY_ERR_UNSUPPORTED;
}

std::size_t instruction_count(const void* context) {
    return context ? static_cast<const arm64_context_t*>(context)->count : 0;
}

const decompatty_instruction* instruction_at(const void* context, std::size_t index) {
    const auto* ctx = static_cast<const arm64_context_t*>(context);
    if (!ctx || !ctx->instructions || index >= ctx->count)
        return nullptr;

    return &ctx->instructions[index];
}

const char* string_at(const void* context, std::uint32_t offset) {
    const auto* ctx = static_cast<const arm64_context_t*>(context);
    if (!ctx || offset >= ctx->pool_used)
        return "";

    return ctx->pool + offset;
}

const decompatty_arch_api API = {
    .struct_size = sizeof(decompatty_arch_api),
    .abi_version = DECOMPATTY_ABI_VERSION,
    .cpu = DECOMPATTY_CPU_ARM64,
    .formats = DECOMPATTY_FORMAT_MACHO | DECOMPATTY_FORMAT_ELF,
    .bitness = 64,
    .endianness = 1,
    .name = "arm64",
    .create = create,
    .destroy = destroy,
    .disassemble = disassemble,
    .instruction_count = instruction_count,
    .instruction_at = instruction_at,
    .string_at = string_at,
};

extern "C" DECOMPATTY_ABI_EXPORT const decompatty_arch_api* decompatty_arch_api_v1(void) {
    return &API;
}
