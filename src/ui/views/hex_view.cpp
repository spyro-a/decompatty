#include <QPlainTextEdit>
#include <QBoxLayout>

#include <ui/views/hex_view.hpp>

#include <utils/utils.hpp>

// this entire tab is proof-of-concept, realistially we won't render millions of characters simultaneously
hex_view_t::hex_view_t(std::uint64_t image_base, std::span<const std::byte> data, QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* hex_view = new QPlainTextEdit(this);
    hex_view->setObjectName("hex_view");
    hex_view->setReadOnly(true);
    hex_view->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    QString body;
    const std::size_t byte_count = data.size();

    for (std::size_t i = 0; i < byte_count; i += line_width) {
        const std::size_t remaining = std::min<std::size_t>(line_width, byte_count - i);

        QString line = "0x" + utils::hex(static_cast<std::byte>(image_base + i));

        for (std::size_t j = 0; j < line_width; j++) {
            if (j == line_width / 2)
                line += " "; // gap between 8-byte groups

            if (j < remaining)
                line += " " + utils::hex(data[i + j], 2);
            else
                line += "   "; // pad short final line
        }

        line += "  ";

        for (std::size_t j = 0; j < remaining; j++) {
            const auto c = std::to_integer<unsigned char>(data[i + j]);
            line += (c >= 0x20 && c <= 0x7E) ? QChar(c) : QChar('.');
        }

        body += line + '\n';
    }

    hex_view->setPlainText(body);

    layout->addWidget(hex_view);
}