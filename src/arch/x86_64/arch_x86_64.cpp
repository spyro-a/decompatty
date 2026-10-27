#include <abi/decompatty_arch.h>

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>

struct x86_64_context_t {
    LLVMDisasmContextRef decoder = nullptr;
    std::vector<decompatty_instruction> instructions;
    std::vector<std::string> strings;
    std::unordered_map<std::string, std::uint32_t> string_index;

    ~x86_64_context_t() {
        if (decoder)
            LLVMDisasmDispose(decoder);
    }

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

    *out_context = nullptr;
    static std::once_flag initialized;
    std::call_once(initialized, [] {
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86Disassembler();
    });

    auto* ctx = new (std::nothrow) x86_64_context_t();
    if (!ctx)
        return DECOMPATTY_ERR_NOMEM;

    ctx->decoder = LLVMCreateDisasm("x86_64-unknown-unknown", nullptr, 0, nullptr, nullptr);
    if (!ctx->decoder) {
        delete ctx;
        return DECOMPATTY_ERR_UNSUPPORTED;
    }

    // Intel syntax, with hexadecimal immediates.
    if (!LLVMSetDisasmOptions(ctx->decoder, LLVMDisassembler_Option_AsmPrinterVariant |
                                           LLVMDisassembler_Option_PrintImmHex)) {
        delete ctx;
        return DECOMPATTY_ERR_UNSUPPORTED;
    }

    *out_context = ctx;
    log_to_host(host, "x86_64: LLVM decoder instance created");
    return DECOMPATTY_OK;
}

void destroy(void* context) {
    delete static_cast<x86_64_context_t*>(context);
}

decompatty_status disassemble(void* context, const decompatty_section* section, const decompatty_host* host) {
    if (!context || !section || !section->data ||
        section->length > std::numeric_limits<std::uint32_t>::max() ||
        section->length > std::numeric_limits<std::uint64_t>::max() - section->address)
        return DECOMPATTY_ERR_INVAL;

    auto* ctx = static_cast<x86_64_context_t*>(context);
    ctx->instructions.clear();
    ctx->strings.clear();
    ctx->string_index.clear();

    try {
        std::size_t decoded = 0;
        for (std::uint64_t offset = 0; offset < section->length;) {
            char text[512]{};
            // LLVM's C API takes a mutable pointer; copy at most one x86 instruction.
            std::uint8_t bytes[15];
            const auto remaining = std::min<std::uint64_t>(sizeof(bytes), section->length - offset);
            std::copy_n(section->data + offset, remaining, bytes);
            auto length = LLVMDisasmInstruction(ctx->decoder, bytes, remaining,
                                               section->address + offset, text, sizeof(text));

            std::string mnemonic;
            std::string operands;
            if (length == 0) {
                length = 1;
                mnemonic = ".byte";
                char value[8];
                std::snprintf(value, sizeof(value), "0x%02x", bytes[0]);
                operands = value;
            } else {
                ++decoded;
                const std::string line(text);
                const auto start = line.find_first_not_of(" \t");
                const auto end = line.find_first_of(" \t", start);
                mnemonic = line.substr(start, end - start);
                if (end != std::string::npos) {
                    const auto operand_start = line.find_first_not_of(" \t", end);
                    const auto operand_end = line.find_last_not_of(" \t\r\n");
                    if (operand_start != std::string::npos)
                        operands = line.substr(operand_start, operand_end - operand_start + 1);
                }
            }

            const bool branch = mnemonic[0] == 'j' || mnemonic == "call" ||
                                mnemonic == "ret" || mnemonic.starts_with("loop");
            decompatty_instruction out{};
            out.address = section->address + offset;
            out.section_offset = static_cast<std::uint32_t>(offset);
            out.mnemonic_offset = ctx->intern(mnemonic);
            out.operands_offset = ctx->intern(operands);
            out.length = static_cast<std::uint8_t>(length);
            out.flags = branch ? DECOMPATTY_INSTR_BRANCH : 0;
            ctx->instructions.push_back(out);
            offset += length;
        }

        char summary[128];
        std::snprintf(summary, sizeof(summary), "x86_64: decoded %zu instructions, %zu undecodable bytes",
                      decoded, ctx->instructions.size() - decoded);
        log_to_host(host, summary);
        return DECOMPATTY_OK;
    } catch (const std::bad_alloc&) {
        ctx->instructions.clear();
        return DECOMPATTY_ERR_NOMEM;
    }
}

std::size_t instruction_count(const void* context) {
    return context ? static_cast<const x86_64_context_t*>(context)->instructions.size() : 0;
}

const decompatty_instruction* instruction_at(const void* context, std::size_t index) {
    const auto* ctx = static_cast<const x86_64_context_t*>(context);
    if (!ctx || index >= ctx->instructions.size())
        return nullptr;

    return &ctx->instructions[index];
}

const char* string_at(const void* context, std::uint32_t offset) {
    const auto* ctx = static_cast<const x86_64_context_t*>(context);
    if (!ctx || offset >= ctx->strings.size())
        return "";

    return ctx->strings[offset].c_str();
}

const decompatty_arch_api API = {
    .struct_size = sizeof(decompatty_arch_api),
    .abi_version = DECOMPATTY_ABI_VERSION,
    .cpu = DECOMPATTY_CPU_X86_64,
    .formats = DECOMPATTY_FORMAT_MACHO | DECOMPATTY_FORMAT_PE,
    .bitness = 64,
    .endianness = 1,
    .name = "x86_64",
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
