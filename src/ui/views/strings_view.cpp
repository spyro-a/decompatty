#include <ui/views/strings_view.hpp>

#include <QFontDatabase>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

namespace {
    QString display_string(const std::string& value) {
        QString result;
        const auto text = QString::fromStdString(value);

        for (const auto c : text) {
            switch (c.unicode()) {
                case '\\': result += QStringLiteral("\\\\"); break;
                case '\n': result += QStringLiteral("\\n"); break;
                case '\r': result += QStringLiteral("\\r"); break;
                case '\t': result += QStringLiteral("\\t"); break;
                case '\0': result += QStringLiteral("\\0"); break;
                case '\a': result += QStringLiteral("\\a"); break;
                case '\b': result += QStringLiteral("\\b"); break;
                case '\f': result += QStringLiteral("\\f"); break;
                case '\v': result += QStringLiteral("\\v"); break;
                default:
                    if (c.unicode() < 0x20 || (c.unicode() >= 0x7F && c.unicode() <= 0x9F))
                        result += QStringLiteral("\\x%1").arg(static_cast<unsigned>(c.unicode()), 2, 16, QLatin1Char('0'));
                    else if (c.unicode() == 0x2028 || c.unicode() == 0x2029)
                        result += QStringLiteral("\\u%1").arg(static_cast<unsigned>(c.unicode()), 4, 16, QLatin1Char('0'));
                    else
                        result += c;
                    break;
            }
        }

        return result;
    }
}

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
        item->setText(2, display_string(s.value));

        // values used for sorting
        item->setData(0, Qt::UserRole, QVariant::fromValue(s.address));
        item->setData(1, Qt::UserRole, QVariant::fromValue(s.value.size()));
    }

    tree->resizeColumnToContents(0);
    tree->resizeColumnToContents(1);

    tree->setSortingEnabled(true);

    layout->addWidget(tree);
}