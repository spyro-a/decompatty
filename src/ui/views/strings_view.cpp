#include <ui/views/strings_view.hpp>

#include <QFontDatabase>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

strings_view_t::strings_view_t(const std::vector<string_t>& strings, QWidget* parent)
    : strings_(strings), QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* tree = new QTreeWidget(this);
    tree->setColumnCount(3);
    tree->setHeaderLabels({"Address", "Size", "String"});
    tree->setAlternatingRowColors(true);
    tree->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    for (const auto& s : strings_) {
        auto* item = new string_item_t(tree);

        // display values
        item->setText(0, QStringLiteral("0x%1").arg(s.address, 0, 16));

        item->setText(1, QString::number(s.value.size()));
        item->setText(2, QString::fromStdString(s.value));

        // values used for sorting
        item->setData(0, Qt::UserRole, QVariant::fromValue(s.address));
        item->setData(1, Qt::UserRole, QVariant::fromValue(s.value.size()));
    }

    tree->resizeColumnToContents(0);
    tree->resizeColumnToContents(1);

    tree->setSortingEnabled(true);

    layout->addWidget(tree);
}