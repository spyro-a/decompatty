#pragma once

#include <format/binary_file.hpp>

#include <QWidget>
#include <QTreeWidgetItem>

#include <vector>

class string_item_t : public QTreeWidgetItem {
public:
    explicit string_item_t(QTreeWidget* parent) : QTreeWidgetItem(parent) {}

    bool operator<(const QTreeWidgetItem& other) const override {
        const int column = treeWidget()->sortColumn();

        if (column == 0 || column == 1) {
            return data(column, Qt::UserRole).toULongLong()
                 < other.data(column, Qt::UserRole).toULongLong();
        }

        return text(column) < other.text(column);
    }
};

class strings_view_t : public QWidget {
    Q_OBJECT
public:
    explicit strings_view_t(const std::vector<string_t>& strings, QWidget* parent = nullptr);

private:
    std::vector<string_t> strings_;
};