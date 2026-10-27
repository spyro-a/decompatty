#include <ui/views/disassembly_view.hpp>

#include <QColor>
#include <QFontDatabase>
#include <QHeaderView>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

#include <utils/utils.hpp>

#include <algorithm>
#include <limits>

disassembly_model_t::disassembly_model_t(std::shared_ptr<const binary_file_t> binary, QObject* parent)
    : QAbstractTableModel(parent), binary_(std::move(binary)) {}

int disassembly_model_t::rowCount(const QModelIndex& parent) const {
    return parent.isValid() || ends_.empty() ? 0 : static_cast<int>(ends_.back());
}

int disassembly_model_t::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : 4;
}

QVariant disassembly_model_t::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return {};
    const char* labels[]{"Address", "Bytes", "Mnemonic", "Operands"};
    return section >= 0 && section < 4 ? QVariant(labels[section]) : QVariant{};
}

QVariant disassembly_model_t::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() ||
        index.column() < 0 || index.column() >= 4)
        return {};

    const auto row = static_cast<std::size_t>(index.row());
    const auto batch = std::upper_bound(ends_.begin(), ends_.end(), row) - ends_.begin();
    const auto start = batch == 0 ? 0 : ends_[batch - 1];
    const auto& instruction = (*batches_[batch])[row - start];

    if (role == Qt::ForegroundRole && index.column() == 2 && (instruction.flags & DECOMPATTY_INSTR_BRANCH))
        return QColor(0x2E, 0xA0, 0x43);
    if (role == Qt::UserRole) {
        if (index.column() == 0)
            return QVariant::fromValue(instruction.address);
        if (index.column() == 1)
            return QVariant::fromValue(instruction.file_offset);
        return QString::fromStdString(index.column() == 2 ? instruction.mnemonic : instruction.operands);
    }
    if (role != Qt::DisplayRole)
        return {};

    switch (index.column()) {
        case 0:
            return QStringLiteral("0x%1").arg(instruction.address, 0, 16);
        case 1: {
            QString bytes;
            const auto data = binary_->data();
            if (instruction.file_offset < data.size()) {
                const auto count = std::min<std::size_t>(instruction.length, data.size() - instruction.file_offset);
                for (std::size_t i = 0; i < count; ++i) {
                    if (i)
                        bytes += ' ';
                    bytes += utils::hex(data[instruction.file_offset + i]);
                }
            }
            return bytes;
        }
        case 2:
            return QString::fromStdString(instruction.mnemonic);
        case 3:
            return QString::fromStdString(instruction.operands);
        default:
            return {};
    }
}

void disassembly_model_t::append(instruction_batch_t batch) {
    if (!batch || batch->empty())
        return;
    const auto start = rowCount();
    if (batch->size() > static_cast<std::size_t>(std::numeric_limits<int>::max() - start))
        return;

    const auto end = start + static_cast<int>(batch->size());
    beginInsertRows({}, start, end - 1);
    batches_.push_back(std::move(batch));
    ends_.push_back(end);
    endInsertRows();
}

disassembly_view_t::disassembly_view_t(std::shared_ptr<const binary_file_t> binary, QWidget* parent)
    : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    model_ = new disassembly_model_t(std::move(binary), this);
    auto* proxy = new QSortFilterProxyModel(this);
    proxy->setSourceModel(model_);
    proxy->setSortRole(Qt::UserRole);
    proxy->setDynamicSortFilter(false);

    auto* table = new QTableView(this);
    table->setObjectName("disassembly_table");
    table->setModel(proxy);
    table->setAlternatingRowColors(true);
    table->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    table->setWordWrap(false);
    table->setShowGrid(false);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->hide();
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setDefaultSectionSize(table->fontMetrics().height() + 6);
    table->setColumnWidth(0, 160);
    table->setColumnWidth(1, 220);
    table->setColumnWidth(2, 120);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setSortingEnabled(true);
    table->sortByColumn(-1, Qt::AscendingOrder);
    layout->addWidget(table);
}

void disassembly_view_t::append(instruction_batch_t batch) {
    model_->append(std::move(batch));
}
