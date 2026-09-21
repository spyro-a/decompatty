#include "ui/views/disassembly_view.hpp"

#include <format/binary_format.hpp>

#include <QVBoxLayout>


namespace {
    const char* format_name(binary_format_t format) {
        switch (format) {
            case binary_format_t::pe: return "PE";
            case binary_format_t::elf: return "ELF";
            case binary_format_t::macho: return "Mach-O";
            default: return "unknown";
        }
    }

    const char* cpu_name(cpu_type_t cpu) {
        switch (cpu) {
            case cpu_type_t::arm: return "ARM";
            case cpu_type_t::x86: return "x86";
            case cpu_type_t::power_pc: return "PowerPC";
            case cpu_type_t::risc_v: return "RISC-V";
            case cpu_type_t::mips: return "MIPS";
            case cpu_type_t::sparc: return "SPARC";
            default: return "unknown";
        }
    }

    const char* bitness_name(bitness_t bitness) {
        switch (bitness) {
            case bitness_t::bits_32: return "32-bit";
            case bitness_t::bits_64: return "64-bit";
            default: return "unknown";
        }
    }

    const char* endianness_name(endianness_t endianness) {
        switch (endianness) {
            case endianness_t::little: return "little-endian";
            case endianness_t::big: return "big-endian";
            default: return "unknown";
        }
    }
}

disassembly_view_t::disassembly_view_t(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
}