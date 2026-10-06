#include <abi/decompatty_arch.h>

#include <arm64_decode.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <string>
#include <vector>
#include <unordered_map>

struct arm64_context_t {
    std::vector<decompatty_instruction> instructions;
    std::vector<std::string> strings;   // mnemonic / operands
    std::unordered_map<std::string, std::uint32_t> string_index;
    std::uint64_t base = 0;

    std::uint32_t intern(const std::string& text) {
        if (const auto it = string_index.find(text); it != string_index.end())
            return it->second;

        const auto index = static_cast<std::uint32_t>(strings.size());
        strings.push_back(text);
        string_index.emplace(strings.back(), index);
        return index;
    }
};

void log_to_host(const decompatty_host* host, const char* msg) {
    if (host && host->log)
        host->log(host->log_context, msg);
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

decompatty_status disassemble(void* context, const decompatty_section* section, const decompatty_host* host) noexcept {
    if (!context || !section || !section->data || section->length == 0)
        return DECOMPATTY_ERR_INVAL;

    auto* ctx = static_cast<arm64_context_t*>(context);
    ctx->instructions.clear();
    ctx->base = section->address;

    std::size_t decoded = 0;

    for (std::uint64_t offset = 0; offset + 4 <= section->length; offset += 4) {
        const auto* p = section->data + offset;

        std::uint32_t bits = 0;
        for (int i = 0; i < 4; ++i)
            bits |= static_cast<std::uint32_t>(p[i]) << (i * 8);

        arm64_instruction_t instruction;
        if (!arm64_decode(bits, section->address + offset, instruction))
            break;
        if (instruction.decoded)
            ++decoded;

        decompatty_instruction out{};
        out.address = section->address + offset;
        out.section_offset = static_cast<std::uint32_t>(offset);
        out.mnemonic_offset = ctx->intern(instruction.mnemonic);
        out.operands_offset = ctx->intern(instruction.operands);
        out.length = instruction.length;
        out.flags = instruction.branch ? DECOMPATTY_INSTR_BRANCH : 0;

        ctx->instructions.push_back(out);
    }

    char summary[96];
    const auto total = ctx->instructions.size();
    std::snprintf(summary, sizeof(summary), "arm64: decoded __text %zu/%zu (%.1f%%)", decoded, total,
                  total ? 100.0 * static_cast<double>(decoded) / static_cast<double>(total) : 0.0);
    log_to_host(host, summary);
    return DECOMPATTY_OK;
}

std::size_t instruction_count(const void* context) {
    return context ? static_cast<const arm64_context_t*>(context)->instructions.size() : 0;
}

const decompatty_instruction* instruction_at(const void* context, std::size_t index) {
    const auto* ctx = static_cast<const arm64_context_t*>(context);
    if (!ctx || index >= ctx->instructions.size())
        return nullptr;

    return &ctx->instructions[index];
}

const char* string_at(const void* context, std::uint32_t offset) {
    const auto* ctx = static_cast<const arm64_context_t*>(context);
    if (!ctx || offset >= ctx->strings.size())
        return "";

    return ctx->strings[offset].c_str();
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
