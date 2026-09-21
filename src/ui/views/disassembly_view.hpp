#pragma once

#include <QtWidgets/qwidget.h>

#include <format/binary_file.hpp>

#include <vector>

#include <ui/views/listing.hpp>

class QPlainTextEdit;

class disassembly_view_t : public QWidget {
    Q_OBJECT
public:
    explicit disassembly_view_t(QWidget* parent = nullptr);

    void set_binary(const binary_file_t& binary);

private:
    void generate_listing();
    void render();

    std::vector<listing_line_t> lines_;

    QPlainTextEdit* listing_ = nullptr;
    const binary_file_t* binary_ = nullptr;
};