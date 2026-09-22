#pragma once

#include <QWidget>

class QPlainTextEdit;

class hex_view_t : public QWidget {
    Q_OBJECT
public:
    explicit hex_view_t(std::uint64_t image_base, std::span<const std::byte> data, QWidget* parent = nullptr);

private:
    std::uint8_t line_width = 16;
};