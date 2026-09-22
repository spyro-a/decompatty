#pragma once

#include <QtWidgets/qwidget.h>

#include <format/binary_file.hpp>

class QPlainTextEdit;

class disassembly_view_t : public QWidget {
    Q_OBJECT
public:
    explicit disassembly_view_t(QWidget* parent = nullptr);
};