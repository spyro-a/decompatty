#include <QFontDatabase>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <format/binary_format.hpp>

#include <ui/views/disassembly_view.hpp>

#include <utils/utils.hpp>

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
            case cpu_type_t::arm64: return "ARM";
            case cpu_type_t::x86_64: return "x86_64";
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

disassembly_view_t::disassembly_view_t(const std::vector<instruction_t>& instructions,
                                       std::span<const std::byte> data, QWidget* parent)
    : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* tree = new QTreeWidget(this);
    tree->setObjectName("disassembly_tree");
    tree->setColumnCount(4);
    tree->setHeaderLabels({"Address", "Bytes", "Mnemonic", "Operands"});
    tree->setAlternatingRowColors(true);
    tree->setUniformRowHeights(true);
    tree->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    tree->setUpdatesEnabled(false);

    for (const auto& instruction : instructions) {
        auto* item = new instruction_item_t(tree);

        item->setText(0, QStringLiteral("0x%1").arg(instruction.address, 0, 16));

        QString bytes;
        const std::size_t start = instruction.file_offset;

        if (start < data.size()) {
            const std::size_t count = std::min<std::size_t>(instruction.length, data.size() - start);

            for (std::size_t i = 0; i < count; ++i) {
                if (i)
                    bytes += ' ';

                bytes += utils::hex(data[start + i]);
            }
        }

        item->setText(1, bytes);
        item->setText(2, QString::fromStdString(instruction.mnemonic));
        item->setText(3, QString::fromStdString(instruction.operands));

        if (instruction.flags & DECOMPATTY_INSTR_BRANCH)
            item->setForeground(2, QBrush(QColor(0x2E, 0xA0, 0x43)));

        item->setData(0, Qt::UserRole, QVariant::fromValue(instruction.address));
        item->setData(1, Qt::UserRole, QVariant::fromValue(instruction.file_offset));
    }

    tree->setUpdatesEnabled(true);

    tree->resizeColumnToContents(0);
    tree->resizeColumnToContents(1);

    tree->sortItems(0, Qt::AscendingOrder);
    tree->setSortingEnabled(true);

    layout->addWidget(tree);
}
