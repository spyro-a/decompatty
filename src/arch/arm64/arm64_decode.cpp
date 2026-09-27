#include <arm64_decode.hpp>

#include <array>

enum class operation_identifier_t {
    unknown,
    nop,
    ret,
    br,
    b,
    bl
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
};

// constexpr std::uint32_t register_number_field_mask = 0b00000000'00000000'00000011'11100000;
// constexpr std::uint32_t field_imm26 = 0b00000011'11111111'11111111'11111111;

constexpr std::uint32_t register_number_field_mask = 0x000003E0u;
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
            out.operands = reg64((bits & register_number_field_mask) >> 5);
            break;

        case operation_identifier_t::b:
        case operation_identifier_t::bl: {
            out.branch = true;
            const auto delta = sign_extend(bits & field_imm26, 26) * 4;
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(address + delta));
            out.operands = buf;
            break;
        }

        default:
            break;
    }

    return true;
}