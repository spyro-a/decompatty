#include <QVBoxLayout>
#include <QDockWidget>
#include <QScrollBar>

#include <ui/views/output_view.hpp>

output_view_t::output_view_t(const QString& name, QWidget* parent) : QDockWidget(name, parent) {
    auto* container = new QWidget(this);
    auto* layout = new QVBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);

    output_ = new QPlainTextEdit(container);
    output_->setObjectName("output_field");
    output_->setReadOnly(true);
    output_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    output_->setMaximumBlockCount(5000);

    input_ = new QLineEdit(container);
    input_->setObjectName("input_field");

    layout->addWidget(output_);
    layout->addWidget(input_);

    setWidget(container);

    connect(input_, &QLineEdit::returnPressed, this, [this] {
        const auto command = input_->text();

        if (command.isEmpty())
            return;

        emit command_entered(command);

        input_->clear();
    });
}

void output_view_t::append(const QString& text) {
    output_->appendPlainText(text);
    auto* bar = output_->verticalScrollBar();
    bar->setValue(bar->maximum());
}

void output_view_t::clear() {
    output_->clear();
}