#pragma once

#include <format/binary_file.hpp>

#include <QAbstractTableModel>
#include <QWidget>

class disassembly_model_t : public QAbstractTableModel {
public:
    explicit disassembly_model_t(std::shared_ptr<const binary_file_t> binary, QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void append(instruction_batch_t batch);

private:
    std::shared_ptr<const binary_file_t> binary_;
    std::vector<instruction_batch_t> batches_;
    std::vector<std::size_t> ends_;
};

class disassembly_view_t : public QWidget {
    Q_OBJECT
public:
    explicit disassembly_view_t(std::shared_ptr<const binary_file_t> binary, QWidget* parent = nullptr);
    void append(instruction_batch_t batch);

private:
    disassembly_model_t* model_ = nullptr;
};
