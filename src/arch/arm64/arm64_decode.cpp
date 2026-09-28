#include <arm64_decode.hpp>

#include <array>

enum class operation_identifier_t {
    unknown,
    nop,
    ret,
    br,
    b,
    bl,
    ldr_imm
};

struct entry_t {
    std::uint32_t mask;
    std::uint32_t value;
    operation_identifier_t id;
    const char* mnemonic;
};

constexpr std::array table = {
    entry_t{0xFFFFFFFFu, 0xD503201Fu, operation_identifier_t::nop, "nop"},
    entry_t{0xFFFFFC1Fu, 0xD65F0000u, operation_identifier_t::ret, "ret"},
    entry_t{0xFFFFFC1Fu, 0xD61F0000u, operation_identifier_t::br, "br"},
    entry_t{0xFC000000u, 0x14000000u, operation_identifier_t::b, "b"},
    entry_t{0xFC000000u, 0x94000000u, operation_identifier_t::bl, "bl"},
    entry_t{0xFFC00000u, 0xF9400000u, operation_identifier_t::ldr_imm, "ldr"},
    entry_t{0xFFC00000u, 0xB9400000u, operation_identifier_t::ldr_imm, "ldr"},   // opc=10 -> w, x4
    entry_t{0xFFC00000u, 0x3DC00000u, operation_identifier_t::ldr_imm, "ldr"},   // opc=00,V=1 -> q, x16
};

constexpr std::uint32_t field_rd = 0x0000001Fu; // register destination
constexpr std::uint32_t field_rn = 0x000003E0u; // register number
constexpr std::uint32_t field_imm12 = 0x003FFC00u;
constexpr std::uint32_t field_imm26 = 0x03FFFFFFu;

std::int64_t sign_extend(std::uint32_t value, std::uint32_t bits) {
    const std::uint32_t shift = 32 - bits;
    return static_cast<std::int32_t>(value << shift) >> shift;
}

std::string reg64(std::uint32_t n) {
    if (n == 31)
        return "xzr";

    return "x" + std::to_string(n);
}

std::string reg_sp(std::uint32_t n) {
    if (n == 31)
        return "sp";
    return "x" + std::to_string(n);
}

bool arm64_decode(std::uint32_t bits, std::uint64_t address, arm64_instruction_t& out) {
    out = {};
    out.bits = bits;

    const entry_t* match = nullptr;
    for (const auto& entry : table)
        if ((bits & entry.mask) == entry.value) {
            match = &entry;
            break;
        }

    if (!match) {
        out.mnemonic = ".inst";
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08x", bits);
        out.operands = buf;
        return true;
    }

    out.mnemonic = match->mnemonic;

    char buf[32];
    switch (match->id) {
        case operation_identifier_t::nop:
            break;

        case operation_identifier_t::ret:
        case operation_identifier_t::br:
            out.branch = true;
            out.operands = reg64((bits & field_rn) >> 5);
            break;

        case operation_identifier_t::b:
        case operation_identifier_t::bl: {
            out.branch = true;
            const auto delta = sign_extend(bits & field_imm26, 26) * 4;
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(address + delta));
            out.operands = buf;
            break;
        }

        case operation_identifier_t::ldr_imm: {
            const auto opc = (bits >> 30) & 0x3;
            const auto vec = (bits >> 26) & 0x1;
            const char* pre = (vec ? "q" : (opc == 2 ? "w" : "x"));
            const auto scale = (vec ? 16ull : (opc == 2 ? 4ull : 8ull));
            const auto imm12 = (bits & field_imm12) >> 10;
            const auto rn = (bits & field_rn) >> 5;
            const auto rt = bits & field_rd;
            const auto base = reg_sp(rn);   // sp, or x<rn>
            if (imm12)
                std::snprintf(buf, sizeof(buf), "%s%u, [%s, #0x%llx]", pre, rt, base.c_str(),
                              static_cast<unsigned long long>(imm12 * scale));
            else
                std::snprintf(buf, sizeof(buf), "%s%u, [%s]", pre, rt, base.c_str());
            out.operands = buf;
            break;
        }

        default:
            break;
    }

    return true;
}