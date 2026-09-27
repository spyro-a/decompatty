#pragma once

#include <format/binary_file.hpp>

#include <QWidget>
#include <QTreeWidgetItem>

#include <span>
#include <vector>

class instruction_item_t : public QTreeWidgetItem {
public:
    explicit instruction_item_t(QTreeWidget* parent) : QTreeWidgetItem(parent) {}

    bool operator<(const QTreeWidgetItem& other) const override {
        const int column = treeWidget()->sortColumn();

        if (column == 0 || column == 1)
            return data(column, Qt::UserRole).toULongLong()
                 < other.data(column, Qt::UserRole).toULongLong();

        return text(column) < other.text(column);
    }
};

class disassembly_view_t : public QWidget {
    Q_OBJECT
public:
    disassembly_view_t(const std::vector<instruction_t>& instructions,
                       std::span<const std::byte> data, QWidget* parent = nullptr);
};
