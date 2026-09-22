#include <QVBoxLayout>
#include <QLineEdit>
#include <QTreeWidget>

#include <ui/views/functions_view.hpp>

functions_view_t::functions_view_t(const QString& name, QWidget* parent) : QDockWidget(name, parent) {
    auto* container = new QWidget(this);
    auto* layout = new QVBoxLayout(container);
    layout->setContentsMargins(QMargins(0, 0, 0, 0));

    search_ = new QLineEdit(container);
    search_->setPlaceholderText("Search functions");

    function_list_ = new QTreeWidget(this);     
    function_list_->setColumnCount(1);
    function_list_->setHeaderLabel("Function name");
    function_list_->setAlternatingRowColors(true);
    function_list_->setSortingEnabled(true);

    layout->addWidget(search_);
    layout->addWidget(function_list_);

    setWidget(container);
}