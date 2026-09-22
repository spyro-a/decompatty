#pragma once

#include <QDockWidget>
#include <QLineEdit>
#include <QPlainTextEdit>

class output_view_t : public QDockWidget {
    Q_OBJECT
public:
    explicit output_view_t(const QString& name, QWidget* parent = nullptr);

    void append(const QString& text);
    void clear();

signals:
    void command_entered(const QString& command);

private:
    QPlainTextEdit* output_ = nullptr;
    QLineEdit* input_ = nullptr;
};