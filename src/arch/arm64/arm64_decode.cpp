#include <arm64_decode.hpp>

#include <array>
#include <cstdio>
#include <string>

enum class operation_identifier_t {
    unknown,
    nop,
    ret,
    br,
    b,
    bl,
    ldr,
    str,
    ldrb,
    strb,
    ldrh,
    strh,
    ldrsw,
    addsub_shifted,
    add_imm,
    sub_imm,
    stp_imm,
    ldp_imm,
    stur,
    ldur,
    cbz,
    cbnz,
    adrp,
    adr,
    mov_reg,
    movz,
    movk,
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
    entry_t{0xFFC00000u, 0x39400000u, operation_identifier_t::ldrb, "ldrb"},
    entry_t{0xFFC00000u, 0x79400000u, operation_identifier_t::ldrh, "ldrh"},
    entry_t{0xFFC00000u, 0xB9400000u, operation_identifier_t::ldr, "ldr"},   // opc=10 -> w, x4
    entry_t{0xFFC00000u, 0xF9400000u, operation_identifier_t::ldr, "ldr"},
    entry_t{0xFFC00000u, 0x3DC00000u, operation_identifier_t::ldr, "ldr"},   // opc=00,V=1 -> q, x16
    entry_t{0xFFC00000u, 0x7DC00000u, operation_identifier_t::ldr, "ldr"},
    entry_t{0xFFC00000u, 0xBDC00000u, operation_identifier_t::ldr, "ldr"},
    entry_t{0xFFC00000u, 0xFDC00000u, operation_identifier_t::ldr, "ldr"},
    entry_t{0xFFC00000u, 0x39000000u, operation_identifier_t::strb, "strb"},
    entry_t{0xFFC00000u, 0x79000000u, operation_identifier_t::strh, "strh"},
    entry_t{0xFFC00000u, 0xB9000000u, operation_identifier_t::str, "str"},
    entry_t{0xFFC00000u, 0xF9000000u, operation_identifier_t::str, "str"},
    entry_t{0xFFC00000u, 0x3D800000u, operation_identifier_t::str, "str"},
    entry_t{0xFFC00000u, 0x7D800000u, operation_identifier_t::str, "str"},
    entry_t{0xFFC00000u, 0xBD800000u, operation_identifier_t::str, "str"},
    entry_t{0xFFC00000u, 0xFD800000u, operation_identifier_t::str, "str"},
    entry_t{0xFFC00000u, 0xB9800000u, operation_identifier_t::ldrsw, "ldrsw"},
    entry_t{0xFF800000u, 0x91000000u, operation_identifier_t::add_imm, "add"},
    entry_t{0xFF800000u, 0xD1000000u, operation_identifier_t::sub_imm, "sub"},
    entry_t{0x7F800000u, 0x11000000u, operation_identifier_t::add_imm, "add"},
    entry_t{0x7F800000u, 0x51000000u, operation_identifier_t::sub_imm, "sub"},
    entry_t{0xFFC00000u, 0xA9000000u, operation_identifier_t::stp_imm, "stp"},
    entry_t{0x7FC00000u, 0x29000000u, operation_identifier_t::stp_imm, "stp"},
    entry_t{0xFFC00000u, 0xA9400000u, operation_identifier_t::ldp_imm, "ldp"},
    entry_t{0x7FC00000u, 0x29400000u, operation_identifier_t::ldp_imm, "ldp"},
    entry_t{0x3FE00000u, 0x38000000u, operation_identifier_t::stur, "stur"},
    entry_t{0x3FE00000u, 0x38400000u, operation_identifier_t::ldur, "ldur"},
    entry_t{0x7F000000u, 0x34000000u, operation_identifier_t::cbz, "cbz"},
    entry_t{0x7F000000u, 0x35000000u, operation_identifier_t::cbnz, "cbnz"},
    entry_t{0x9F000000u, 0x90000000u, operation_identifier_t::adrp, "adrp"},
    entry_t{0x9F000000u, 0x10000000u, operation_identifier_t::adr, "adr"},
    entry_t{0xFF800000u, 0xB1000000u, operation_identifier_t::add_imm, "adds"},
    entry_t{0xFF800000u, 0xF1000000u, operation_identifier_t::sub_imm, "subs"},
    entry_t{0x7F800000u, 0x31000000u, operation_identifier_t::add_imm, "adds"},
    entry_t{0x7F800000u, 0x71000000u, operation_identifier_t::sub_imm, "subs"},
    entry_t{0xFFE0FFE0u, 0xAA0003E0u, operation_identifier_t::mov_reg, "mov"},
    entry_t{0x7FE0FFE0u, 0x2A0003E0u, operation_identifier_t::mov_reg, "mov"},
    entry_t{0x7F800000u, 0x12800000u, operation_identifier_t::movz, "mov"},
    entry_t{0xFF800000u, 0x92800000u, operation_identifier_t::movz, "mov"},
    entry_t{0xFFE0FC00u, 0x8B000000u, operation_identifier_t::addsub_shifted, "add"},
    entry_t{0xFFE0FC00u, 0xCB000000u, operation_identifier_t::addsub_shifted, "sub"},
    entry_t{0xFFE0FC00u, 0xAB000000u, operation_identifier_t::addsub_shifted, "adds"},
    entry_t{0xFFE0FC00u, 0xEB000000u, operation_identifier_t::addsub_shifted, "subs"},
    entry_t{0x7FE0FC00u, 0x0B000000u, operation_identifier_t::addsub_shifted, "add"},
    entry_t{0x7FE0FC00u, 0x4B000000u, operation_identifier_t::addsub_shifted, "sub"},
    entry_t{0x7FE0FC00u, 0x2B000000u, operation_identifier_t::addsub_shifted, "adds"},
    entry_t{0x7FE0FC00u, 0x6B000000u, operation_identifier_t::addsub_shifted, "subs"},
    entry_t{0xFF800000u, 0xD2800000u, operation_identifier_t::movz, "mov"},
    entry_t{0x7F800000u, 0x52800000u, operation_identifier_t::movz, "mov"},
    entry_t{0xFF800000u, 0xF2800000u, operation_identifier_t::movk, "movk"},
    entry_t{0x7F800000u, 0x72800000u, operation_identifier_t::movk, "movk"},
};

constexpr std::uint32_t field_rt = 0x0000001Fu; // register destination
constexpr std::uint32_t field_rt2 = 0x00007C00u;
constexpr std::uint32_t field_rn = 0x000003E0u; // register number
constexpr std::uint32_t field_imm12 = 0x003FFC00u;
constexpr std::uint32_t field_imm16 = 0x001FFFE0u;
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

std::string reg_sp(std::uint32_t n, const char* prefix = "x") {
    if (n == 31)
        return "sp";
    return std::string(prefix) + std::to_string(n);
}

struct ldst_operand_t {
    const char* value;
    const char* zero;
    std::uint32_t scale;
};

constexpr std::array<ldst_operand_t, 4> scalar_operands = {{
    {.value = "w", .zero = "wzr", .scale = 1},
    {.value = "w", .zero = "wzr", .scale = 2},
    {.value = "w", .zero = "wzr", .scale = 4},
    {.value = "x", .zero = "xzr", .scale = 8},
}};

constexpr std::array<ldst_operand_t, 4> vector_operands = {{
    {.value = "q", .zero = "q31", .scale = 16},
    {.value = "d", .zero = "d31", .scale = 8},
    {.value = "s", .zero = "s31", .scale = 4},
    {.value = "h", .zero = "h31", .scale = 2},
}};

constexpr std::array<ldst_operand_t, 4> ldst_pair_operands = {{
    {.value = "w", .zero = "wzr", .scale = 4},
    {.value = "w", .zero = "wzr", .scale = 4},
    {.value = "x", .zero = "xzr", .scale = 8},
    {.value = "q", .zero = "q31", .scale = 16},
}};

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
    out.decoded = true;

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

        case operation_identifier_t::ldr:
        case operation_identifier_t::str:
        case operation_identifier_t::ldrb:
        case operation_identifier_t::strb:
        case operation_identifier_t::ldrh:
        case operation_identifier_t::strh:
        case operation_identifier_t::ldrsw: {
            const auto opc = (bits >> 30) & 0x3;
            const auto& form = ((bits >> 26) & 0x1) ? vector_operands[opc] : scalar_operands[opc];
            const auto imm12 = (bits & field_imm12) >> 10;
            const auto rn = (bits & field_rn) >> 5;
            const auto rt = bits & field_rt;
            const auto base = reg_sp(rn);
            const bool is_store = match->id == operation_identifier_t::str ||
                                  match->id == operation_identifier_t::strb ||
                                  match->id == operation_identifier_t::strh;
            const bool sign_extend_32 = match->id == operation_identifier_t::ldrsw;
            const auto dst = rt == 31 && is_store
                                 ? std::string(form.zero)
                                 : std::string(sign_extend_32 ? "x" : form.value) + std::to_string(rt);
            if (imm12)
                std::snprintf(buf, sizeof(buf), "%s, [%s, #0x%llx]", dst.c_str(), base.c_str(),
                              static_cast<unsigned long long>(imm12 * form.scale));
            else
                std::snprintf(buf, sizeof(buf), "%s, [%s]", dst.c_str(), base.c_str());
            out.operands = buf;
            break;
        }

        case operation_identifier_t::addsub_shifted: {
            const auto sf = (bits >> 31) & 1;
            const auto shift = (bits >> 22) & 0x3;
            const auto rm = (bits >> 16) & 0x1F;
            const auto imm6 = (bits >> 10) & 0x3F;
            const auto rn = (bits & field_rn) >> 5;
            const auto rd = bits & field_rt;
            const auto is_sub = match->id != operation_identifier_t::add_imm &&
                                (bits >> 30) & 1;

            out.mnemonic = is_sub ? "sub" : "add";
            if ((bits >> 29) & 1) out.mnemonic += "s";

            if (is_sub && rn == 31 && !((bits >> 29) & 1)) {
                out.mnemonic = "neg";
                std::snprintf(buf, sizeof(buf), "%s%s, %s%s",
                              sf ? "x" : "w", std::to_string(rd).c_str(),
                              sf ? "x" : "w", std::to_string(rm).c_str());
                out.operands = buf;
                break;
            }

            const auto prefix = std::string(sf ? "x" : "w");
            if (shift == 0 && imm6 == 0) {
                std::snprintf(buf, sizeof(buf), "%s%s, %s%s, %s%s", prefix.c_str(),
                              std::to_string(rd).c_str(), prefix.c_str(), std::to_string(rn).c_str(),
                              prefix.c_str(), std::to_string(rm).c_str());
            } else {
                static const char* names[] = {"lsl", "lsr", "asr", "ror"};
                std::snprintf(buf, sizeof(buf), "%s%s, %s%s, %s%s, %s #%u", prefix.c_str(),
                              std::to_string(rd).c_str(), prefix.c_str(), std::to_string(rn).c_str(),
                              prefix.c_str(), std::to_string(rm).c_str(), names[shift], imm6);
            }
            out.operands = buf;
            break;
        }

        case operation_identifier_t::add_imm:
        case operation_identifier_t::sub_imm: {
            const auto sf = (bits >> 31) & 1;
            const auto set_flags = (bits >> 29) & 1;
            const auto imm12 = (bits & field_imm12) >> 10;
            const auto shift12 = (bits >> 22) & 1;
            const auto rn = (bits & field_rn) >> 5;
            const auto rd = bits & field_rt;
            const auto is_sub = match->id == operation_identifier_t::sub_imm;
            const auto base = reg_sp(rn, sf ? "x" : "w");

            out.mnemonic = is_sub ? "sub" : "add";
            if (set_flags) out.mnemonic += "s";
            const auto dst = reg_sp(rd, sf ? "x" : "w");

            if (set_flags && rd == 31) {
                out.mnemonic = is_sub ? "cmp" : "cmn";
                std::snprintf(buf, sizeof(buf), "%s, #0x%llx", base.c_str(),
                            static_cast<unsigned long long>(imm12 << (shift12 ? 12 : 0)));
            } else if (!is_sub && !set_flags && rn == 31 && imm12 == 0 && !shift12) {
                out.mnemonic = "mov";
                std::snprintf(buf, sizeof(buf), "%s, sp", dst.c_str());
            } else if (shift12) {
                std::snprintf(buf, sizeof(buf), "%s, %s, #0x%llx, lsl #12", dst.c_str(), base.c_str(),
                            static_cast<unsigned long long>(imm12));
            } else {
                std::snprintf(buf, sizeof(buf), "%s, %s, #0x%llx", dst.c_str(), base.c_str(),
                            static_cast<unsigned long long>(imm12));
            }
            out.operands = buf;
            break;
        }

        case operation_identifier_t::stp_imm:
        case operation_identifier_t::ldp_imm: {
            const auto opc = (bits >> 30) & 0x3;
            const auto& form = ldst_pair_operands[opc];
            const auto rt  = bits & field_rt;
            const auto rt2 = (bits & field_rt2) >> 10;
            const auto rn  = (bits & field_rn) >> 5;
            const auto dst1 = std::string(form.value) + std::to_string(rt);
            const auto dst2 = std::string(form.value) + std::to_string(rt2);
            const auto base = reg_sp(rn);
            const auto offset = sign_extend((bits >> 15) & 0x7F, 7) * form.scale;

            if (offset < 0)
                std::snprintf(buf, sizeof(buf), "%s, %s, [%s, #-0x%llx]", dst1.c_str(), dst2.c_str(),
                            base.c_str(), static_cast<unsigned long long>(-offset));
            else if (offset)
                std::snprintf(buf, sizeof(buf), "%s, %s, [%s, #0x%llx]", dst1.c_str(), dst2.c_str(),
                            base.c_str(), static_cast<unsigned long long>(offset));
            else
                std::snprintf(buf, sizeof(buf), "%s, %s, [%s]", dst1.c_str(), dst2.c_str(), base.c_str());

            out.operands = buf;
            break;
        }

        case operation_identifier_t::stur:
        case operation_identifier_t::ldur: {
            const auto opc = (bits >> 30) & 0x3;
            const auto& form = ((bits >> 26) & 0x1) ? vector_operands[opc] : scalar_operands[opc];
            const auto imm9 = sign_extend((bits >> 12) & 0x1FF, 9);
            const auto rn = (bits & field_rn) >> 5;
            const auto rt = bits & field_rt;
            const auto dst = (rt == 31 && match->id == operation_identifier_t::stur)
                                ? std::string(form.zero)
                                : std::string(form.value) + std::to_string(rt);
            const auto base = reg_sp(rn);

            if (imm9 < 0)
                std::snprintf(buf, sizeof(buf), "%s, [%s, #-0x%llx]", dst.c_str(), base.c_str(),
                            static_cast<unsigned long long>(-imm9));
            else if (imm9)
                std::snprintf(buf, sizeof(buf), "%s, [%s, #0x%llx]", dst.c_str(), base.c_str(),
                            static_cast<unsigned long long>(imm9));
            else
                std::snprintf(buf, sizeof(buf), "%s, [%s]", dst.c_str(), base.c_str());

            out.operands = buf;
            break;
        }

        case operation_identifier_t::cbz:
        case operation_identifier_t::cbnz: {
            out.branch = true;
            const auto delta = sign_extend((bits >> 5) & 0x7FFFF, 19) * 4;
            const auto rt = bits & field_rt;
            const auto reg = (bits >> 31) & 1 ? "x" : "w";
            const auto dst = rt == 31 ? std::string(reg) + "zr" : std::string(reg) + std::to_string(rt);
            std::snprintf(buf, sizeof(buf), "%s, 0x%llx", dst.c_str(),
                        static_cast<unsigned long long>(address + delta));
            out.operands = buf;
            break;
        }

        case operation_identifier_t::adrp:
        case operation_identifier_t::adr: {
            const auto immlo = (bits >> 29) & 0x3;
            const auto immhi = (bits >> 5) & 0x7FFFF;
            const auto imm = sign_extend((immhi << 2) | immlo, 21);
            const auto rd = bits & field_rt;
            const auto dst = ((bits >> 31) & 1 ? "x" : "w") + std::to_string(rd);

            if (match->id == operation_identifier_t::adrp) {
                const auto page = address & ~static_cast<std::uint64_t>(0xFFF);
                std::snprintf(buf, sizeof(buf), "%s, 0x%llx", dst.c_str(),
                            static_cast<unsigned long long>(page + (static_cast<std::int64_t>(imm) << 12)));
            } else {
                std::snprintf(buf, sizeof(buf), "%s, 0x%llx", dst.c_str(),
                            static_cast<unsigned long long>(address + imm));
            }
            out.operands = buf;
            break;
        }

        case operation_identifier_t::mov_reg: {
            const auto sf = (bits >> 31) & 1;
            const auto rd = bits & field_rt;
            const auto rm = (bits >> 16) & 0x1F;
            out.operands = std::string(sf ? "x" : "w") + std::to_string(rd) + ", " +
                            std::string(sf ? "x" : "w") + std::to_string(rm);
            break;
        }

        case operation_identifier_t::movz:
        case operation_identifier_t::movk: {
            const auto sf = (bits >> 31) & 1;
            const auto rd = bits & field_rt;
            const auto hw = (bits >> 21) & 0x3;
            const auto imm = (bits & field_imm16) >> 5;
            const auto inverted = !((bits >> 30) & 1);

            if (match->id == operation_identifier_t::movk) {
                out.mnemonic = "movk";
                if (hw)
                    std::snprintf(buf, sizeof(buf), "%s%s, #0x%x, lsl #%u", sf ? "x" : "w",
                                  std::to_string(rd).c_str(), imm, hw * 16);
                else
                    std::snprintf(buf, sizeof(buf), "%s%s, #0x%x", sf ? "x" : "w",
                                  std::to_string(rd).c_str(), imm);
                out.operands = buf;
                break;
            }

            out.mnemonic = "mov";
            if (sf) {
                const auto wide = static_cast<std::uint64_t>(imm) << (hw * 16);
                const auto value = inverted ? ~wide : wide;
                if (value >> 63)
                    std::snprintf(buf, sizeof(buf), "x%s, #-0x%llx", std::to_string(rd).c_str(),
                                  static_cast<unsigned long long>((~value) + 1));
                else
                    std::snprintf(buf, sizeof(buf), "x%s, #0x%llx", std::to_string(rd).c_str(),
                                  static_cast<unsigned long long>(value));
            } else {
                const auto narrow = static_cast<std::uint32_t>(imm) << (hw * 16);
                const auto value = inverted ? ~narrow : narrow;
                if (value >> 31)
                    std::snprintf(buf, sizeof(buf), "w%s, #-0x%x", std::to_string(rd).c_str(),
                                  static_cast<std::uint32_t>((~value) + 1));
                else
                    std::snprintf(buf, sizeof(buf), "w%s, #0x%x", std::to_string(rd).c_str(), value);
            }
            out.operands = buf;
            break;
        }

        default:
            break;
    }

    return true;
}