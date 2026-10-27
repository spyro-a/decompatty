#pragma once

#include <format/binary_file.hpp>

#include <QAbstractTableModel>
#include <QWidget>
#include <QColor>

#include <unordered_map>

class disassembly_model_t : public QAbstractTableModel {
public:
    enum { label_role = Qt::UserRole + 1, segment_role, branch_role };

    explicit disassembly_model_t(std::shared_ptr<const binary_file_t> binary, QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void append(instruction_batch_t batch);
    int row_for_address(std::uint64_t address) const;

private:
    struct label_t {
        std::size_t row;
        std::uint64_t address;
        QString name;
    };

    std::shared_ptr<const binary_file_t> binary_;
    std::unordered_map<std::uint64_t, QString> symbols_;
    std::vector<label_t> labels_;
    std::vector<instruction_batch_t> batches_;
    std::vector<std::size_t> ends_;
};

class disassembly_view_t : public QWidget {
    Q_OBJECT
    Q_PROPERTY(QColor addressColor MEMBER address_color_)
    Q_PROPERTY(QColor bytesColor MEMBER bytes_color_)
    Q_PROPERTY(QColor labelColor MEMBER label_color_)
    Q_PROPERTY(QColor mnemonicColor MEMBER mnemonic_color_)
    Q_PROPERTY(QColor registerColor MEMBER register_color_)
    Q_PROPERTY(QColor immediateColor MEMBER immediate_color_)
    Q_PROPERTY(QColor controlColor MEMBER control_color_)
public:
    explicit disassembly_view_t(std::shared_ptr<const binary_file_t> binary, QWidget* parent = nullptr);
    void append(instruction_batch_t batch);

private:
    QColor address_color_;
    QColor bytes_color_;
    QColor label_color_;
    QColor mnemonic_color_;
    QColor register_color_;
    QColor immediate_color_;
    QColor control_color_;
    disassembly_model_t* model_ = nullptr;
};
