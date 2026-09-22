#pragma once

#include <QDockWidget>

class QLineEdit;
class QTreeWidget;

class functions_view_t : public QDockWidget {
    Q_OBJECT
public:
    explicit functions_view_t(const QString& name, QWidget* parent = nullptr);

private:
    QLineEdit* search_ = nullptr;
    QTreeWidget* function_list_ = nullptr;
};