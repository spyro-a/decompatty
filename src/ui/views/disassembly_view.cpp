#include <ui/views/disassembly_view.hpp>

#include <format/macho/macho_file.hpp>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QMessageBox>
#include <QPainter>
#include <QRegularExpression>
#include <QShortcut>
#include <QStyledItemDelegate>
#include <QToolButton>
#include <QFontDatabase>
#include <QHeaderView>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

#include <utils/utils.hpp>

#include <algorithm>
#include <limits>

disassembly_model_t::disassembly_model_t(std::shared_ptr<const binary_file_t> binary, QObject* parent)
    : QAbstractTableModel(parent), binary_(std::move(binary)) {
    for (const auto& symbol : binary_->symbols()) {
        // Named section symbols only; exclude debug records and undefined imports.
        if ((symbol.type & 0xE0) == 0 && (symbol.type & 0x0E) == 0x0E && !symbol.name.empty())
            symbols_.try_emplace(symbol.address, QString::fromStdString(symbol.name));
    }
}

int disassembly_model_t::rowCount(const QModelIndex& parent) const {
    return parent.isValid() || ends_.empty() ? 0 : static_cast<int>(ends_.back() + labels_.size());
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
    const auto label = std::lower_bound(labels_.begin(), labels_.end(), row,
                                       [](const label_t& value, std::size_t row) { return value.row < row; });
    const bool is_label = label != labels_.end() && label->row == row;
    const instruction_t* instruction_ptr = nullptr;
    if (!is_label) {
        const auto instruction_row = row - (label - labels_.begin());
        const auto batch = std::upper_bound(ends_.begin(), ends_.end(), instruction_row) - ends_.begin();
        const auto start = batch == 0 ? 0 : ends_[batch - 1];
        instruction_ptr = &(*batches_[batch])[instruction_row - start];
    }
    const auto address = is_label ? label->address : instruction_ptr->address;
    if (role == Qt::ToolTipRole || role == Qt::AccessibleTextRole) {
        const auto address_text = QStringLiteral("0x%1").arg(address, 0, 16);
        if (is_label)
            return address_text + "  " + label->name + ':';
        return address_text + "  " + QString::fromStdString(instruction_ptr->mnemonic) + "  " +
               QString::fromStdString(instruction_ptr->operands);
    }
    if (role == label_role)
        return is_label ? label->name + ':' : QString{};
    if (role == segment_role) {
        if (const auto* macho = dynamic_cast<const macho_file_t*>(binary_.get())) {
            for (const auto& section : macho->sections())
                if (address >= section.address && address - section.address < section.size)
                    return QString::fromStdString(section.section_name);
        }
        return QStringLiteral("text");
    }
    if (is_label) {
        if (role == Qt::UserRole && index.column() == 0)
            return QVariant::fromValue(address);
        if (role == Qt::DisplayRole && index.column() == 0)
            return QStringLiteral("0x%1").arg(address, 0, 16);
        if (role == Qt::DisplayRole && index.column() == 2)
            return label->name + ':';
        return {};
    }
    const auto& instruction = *instruction_ptr;

    if (role == branch_role)
        return (instruction.flags & DECOMPATTY_INSTR_BRANCH) != 0;
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
    std::vector<label_t> labels;
    for (std::size_t i = 0; i < batch->size(); ++i) {
        if (const auto it = symbols_.find((*batch)[i].address); it != symbols_.end())
            labels.push_back({start + i + labels.size(), it->first, it->second});
    }
    const auto count = batch->size() + labels.size();
    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max() - start))
        return;

    beginInsertRows({}, start, start + static_cast<int>(count) - 1);
    const auto instruction_count = ends_.empty() ? 0 : ends_.back();
    ends_.push_back(instruction_count + batch->size());
    batches_.push_back(std::move(batch));
    labels_.insert(labels_.end(), labels.begin(), labels.end());
    endInsertRows();
}

int disassembly_model_t::row_for_address(std::uint64_t address) const {
    for (std::size_t batch = 0; batch < batches_.size(); ++batch) {
        const auto& instructions = *batches_[batch];
        const auto it = std::lower_bound(instructions.begin(), instructions.end(), address,
                                        [](const instruction_t& value, std::uint64_t address) {
                                            return value.address < address;
                                        });
        if (it == instructions.end() || it->address != address)
            continue;
        std::size_t row = (batch == 0 ? 0 : ends_[batch - 1]) + (it - instructions.begin());
        for (const auto& label : labels_) {
            if (label.row > row)
                break;
            ++row;
        }
        return static_cast<int>(row);
    }
    return -1;
}

namespace {
    class listing_delegate_t : public QStyledItemDelegate {
    public:
        bool show_bytes = false;
        int address_digits = 16;
        const disassembly_view_t* view = nullptr;
        using QStyledItemDelegate::QStyledItemDelegate;

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override {
            auto style = option;
            initStyleOption(&style, index);
            style.text.clear();
            const auto* widget = style.widget;
            (widget ? widget->style() : QApplication::style())->drawControl(QStyle::CE_ItemViewItem, &style, painter, widget);

            painter->save();
            painter->setClipRect(option.rect);
            painter->setFont(option.font);
            const auto metrics = option.fontMetrics;
            const int cell = metrics.horizontalAdvance('0');
            const int baseline = option.rect.top() + (option.rect.height() - metrics.height()) / 2 + metrics.ascent();
            int x = option.rect.left() + 12;
            const auto draw = [&](const QString& text, const QColor& color, int position) {
                painter->setPen(color);
                painter->drawText(position, baseline, text);
            };
            const auto color = [&](const char* property) {
                if (option.state & QStyle::State_Selected)
                    return option.palette.color(QPalette::HighlightedText);
                const auto value = view->property(property).value<QColor>();
                return value.isValid() ? value : option.palette.color(QPalette::Text);
            };
            const auto address = index.data(Qt::UserRole).toULongLong();
            const auto segment = index.data(disassembly_model_t::segment_role).toString();
            const auto address_text = segment + ':' + QStringLiteral("%1").arg(address, address_digits, 16, QLatin1Char('0')).toUpper();
            draw(address_text, color("addressColor"), x);
            x += (address_digits + 12) * cell;

            const auto label = index.data(disassembly_model_t::label_role).toString();
            if (!label.isEmpty()) {
                draw(label, color("labelColor"), x + (show_bytes ? 27 * cell : 0));
                painter->restore();
                return;
            }
            if (show_bytes) {
                auto bytes = index.siblingAtColumn(1).data().toString();
                if (bytes.size() > 23)
                    bytes = bytes.left(23) + " …";
                draw(bytes, color("bytesColor"), x);
                x += 27 * cell;
            }
            const auto mnemonic = index.siblingAtColumn(2).data().toString();
            const auto operands = index.siblingAtColumn(3).data().toString();
            const bool control = index.data(disassembly_model_t::branch_role).toBool();
            draw(mnemonic, control ? color("controlColor") : color("mnemonicColor"), x);
            x += std::max(10, static_cast<int>(mnemonic.size()) + 1) * cell;

            static const QRegularExpression tokens(
                R"((\b(?:0x[0-9a-fA-F]+|[0-9]+)\b)|(\b(?:r(?:[0-9]+[bwd]?|ax|bx|cx|dx|si|di|sp|bp|ip)|e(?:ax|bx|cx|dx|si|di|sp|bp|ip)|[abcd][lh]|[wxvqds][0-9]+|[xyz]mm[0-9]+|sp|lr|pc|fp|nzcv)\b))",
                QRegularExpression::CaseInsensitiveOption);
            int offset = 0;
            auto matches = tokens.globalMatch(operands);
            while (matches.hasNext()) {
                const auto token = matches.next();
                const auto plain = operands.mid(offset, token.capturedStart() - offset);
                draw(plain, color("mnemonicColor"), x);
                x += metrics.horizontalAdvance(plain);
                draw(token.captured(), token.captured(1).isEmpty() ? color("registerColor") : color("immediateColor"), x);
                x += metrics.horizontalAdvance(token.captured());
                offset = token.capturedEnd();
            }
            draw(operands.mid(offset), color("mnemonicColor"), x);
            painter->restore();
        }
    };
}

disassembly_view_t::disassembly_view_t(std::shared_ptr<const binary_file_t> binary, QWidget* parent)
    : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* toolbar = new QHBoxLayout();
    toolbar->setContentsMargins(12, 5, 12, 5);
    auto* title = new QLabel("Linear disassembly", this);
    toolbar->addWidget(title);
    toolbar->addStretch();
    auto* bytes = new QCheckBox("Opcode bytes", this);
    bytes->setObjectName("opcode_bytes");
    toolbar->addWidget(bytes);
    auto* jump = new QToolButton(this);
    jump->setText("Go to address…");
    jump->setToolTip("Go to a decoded address (G)");
    toolbar->addWidget(jump);
    layout->addLayout(toolbar);

    const int address_digits = binary->bitness() == bitness_t::bits_32 ? 8 : 16;
    model_ = new disassembly_model_t(std::move(binary), this);
    auto* proxy = new QSortFilterProxyModel(this);
    proxy->setSourceModel(model_);
    proxy->setSortRole(Qt::UserRole);
    proxy->setDynamicSortFilter(false);

    auto* table = new QTableView(this);
    table->setObjectName("disassembly_table");
    table->setModel(proxy);
    table->setAlternatingRowColors(false);
    table->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    table->setWordWrap(false);
    table->setShowGrid(false);
    table->setAccessibleName("Disassembly listing");
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    auto* delegate = new listing_delegate_t(table);
    delegate->address_digits = address_digits;
    delegate->view = this;
    table->setItemDelegate(delegate);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->hide();
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    const int line_height = table->fontMetrics().height() + 1;
    table->verticalHeader()->setMinimumSectionSize(line_height);
    table->verticalHeader()->setDefaultSectionSize(line_height);
    table->horizontalHeader()->hide();
    for (int column = 1; column < 4; ++column)
        table->hideColumn(column);
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table->horizontalHeader()->setMinimumSectionSize(760);
    table->setSortingEnabled(true);
    table->sortByColumn(-1, Qt::AscendingOrder);
    connect(bytes, &QCheckBox::toggled, table, [table, delegate](bool checked) {
        delegate->show_bytes = checked;
        table->horizontalHeader()->setMinimumSectionSize(checked ? 1020 : 760);
        table->viewport()->update();
    });
    auto go_to_address = [this, table, proxy] {
        bool accepted = false;
        auto text = QInputDialog::getText(this, "Go to address", "Hexadecimal address:", QLineEdit::Normal, {}, &accepted).trimmed();
        if (!accepted || text.isEmpty())
            return;
        bool valid = false;
        const auto address = text.toULongLong(&valid, 16);
        const int row = valid ? model_->row_for_address(address) : -1;
        if (row < 0) {
            QMessageBox::information(this, "Address unavailable", "This address has not been decoded.");
            return;
        }
        const auto index = proxy->mapFromSource(model_->index(row, 0));
        table->setCurrentIndex(index);
        table->scrollTo(index, QAbstractItemView::PositionAtCenter);
        table->setFocus();
    };
    connect(jump, &QToolButton::clicked, this, go_to_address);
    auto* shortcut = new QShortcut(QKeySequence("G"), table);
    shortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(shortcut, &QShortcut::activated, this, go_to_address);
    auto* copy = new QShortcut(QKeySequence::Copy, table);
    copy->setContext(Qt::WidgetWithChildrenShortcut);
    connect(copy, &QShortcut::activated, table, [table] {
        const auto index = table->currentIndex();
        if (!index.isValid())
            return;
        QString text = index.data().toString() + "  ";
        for (int column = 1; column < 4; ++column)
            text += index.siblingAtColumn(column).data().toString() + "  ";
        QApplication::clipboard()->setText(text.trimmed());
    });
    layout->addWidget(table);
}

void disassembly_view_t::append(instruction_batch_t batch) {
    if (!batch || batch->empty())
        return;
    const auto address = batch->front().address;
    model_->append(std::move(batch));
    auto* table = findChild<QTableView*>("disassembly_table");
    if (!table->currentIndex().isValid()) {
        const auto* proxy = static_cast<QSortFilterProxyModel*>(table->model());
        table->setCurrentIndex(proxy->mapFromSource(model_->index(model_->row_for_address(address), 0)));
    }
}
