#include "ui/views/disassembly_view.hpp"
#include <QtGui/qaction.h>
#include <QtWidgets/qwidget.h>
#include <core/analysis_engine.hpp>

#include <ui/user_interface.hpp>

#include <utils/utils.hpp>

#include <QAction>
#include <QActionGroup>
#include <QDockWidget>
#include <QFileDialog>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QToolBar>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QBoxLayout>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QLabel>


#include <string>

namespace {
    std::string read_theme(const char* path) {
        const auto data = utils::load_file(path);

        if (!data)
            return {};

        return std::string(
            reinterpret_cast<const char*>(data->data()),
            data->size()
        );
    }
}

user_interface_t::user_interface_t(QWidget* parent) : QMainWindow(parent) {}

bool user_interface_t::setup(const char* app_name, int width, int height) {
    setWindowTitle(app_name);
    resize(width, height);

    setup_ui();

    return true;
}

std::unordered_map<QString, QWidget*>& user_interface_t::views() {
    return views_;
}

void user_interface_t::open_file() {
    const auto path = QFileDialog::getOpenFileName(
        this, "Open Binary", {}, "Binaries (*);;All Files (*)"
    );

    if (path.isEmpty())
        return;

    if (!engine_)
        return;

    engine_->set_logger([this](const std::string& message) {
        log(QString::fromStdString(message));
    });

    if (!engine_->load(path.toLocal8Bit().constData())) {
        statusBar()->showMessage("failed to open: " + path);
        return;
    }

    functions_dock->show();
    main_views->tabBar()->show();

    if (auto* view = show_disassembly_view(); view && engine_->has_binary())
        view->set_binary(*engine_->binary());

    setWindowTitle(QStringLiteral("decompatty - %1").arg(QFileInfo(path).fileName()));
    statusBar()->showMessage("opened: " + path);
}

disassembly_view_t* user_interface_t::show_disassembly_view() {
    if (disassembly_view_)
        return disassembly_view_;

    if (auto* placeholder = main_views->widget(0);
        placeholder && placeholder->objectName() == "intro_label") {
        main_views->removeTab(0);
        placeholder->deleteLater();
    }

    disassembly_view_ = new disassembly_view_t(this);
    disassembly_view_->setObjectName("disassembly_view");

    main_views->addTab(disassembly_view_, "Disassembly");
    main_views->setCurrentWidget(disassembly_view_);

    views_["disassembly_view"] = disassembly_view_;

    return disassembly_view_;
}

QWidget* user_interface_t::add_view(const QString& title, const QString& id) {
    auto* widget = new QWidget(this);
    widget->setObjectName(id);

    auto* text_edit = new QPlainTextEdit(widget);
    auto font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setPointSize(12);
    text_edit->setFont(font);
    text_edit->setReadOnly(true);

    auto* layout = new QVBoxLayout(widget);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(text_edit);

    main_views->addTab(widget, title);
    main_views->setCurrentWidget(widget);

    views_[id] = widget;

    return widget;
}

void user_interface_t::execute_command() {
    const auto command = input->text();

    if (command.isEmpty())
        return;

    output->appendPlainText("> " + command);
    output->appendPlainText(QStringLiteral("\'%1\' is undefined").arg(command));

    input->clear();
}

void user_interface_t::setup_ui() {
    apply_theme();

    setDockOptions(QMainWindow::AnimatedDocks | QMainWindow::AllowNestedDocks | QMainWindow::AllowTabbedDocks);
    setCorner(Qt::BottomLeftCorner, Qt::BottomDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::BottomDockWidgetArea);

    setup_menus();
    setup_toolbar();
    setup_function_list();
    setup_main_views();
    setup_output();
}

void user_interface_t::setup_menus() {
    // layer 1
    QMenu* file = menuBar()->addMenu("&File");
    QMenu* edit = menuBar()->addMenu("&Edit");
    QMenu* search = menuBar()->addMenu("&Search");
    QMenu* view = menuBar()->addMenu("&View");
    QMenu* help = menuBar()->addMenu("&Help");

    // layer 2
    // file
    QAction* open_action = new QAction("&Open", this);
    open_action->setShortcut(QKeySequence::Open);
    file->addAction(open_action);
    connect(open_action, &QAction::triggered, this, &user_interface_t::open_file);

    // view
    QMenu* open_view_menu = view->addMenu("&Open View");
    
    // layer 3
    QAction* open_disassembly_action = new QAction("&Disassembly View");
    open_view_menu->addAction(open_disassembly_action);
    connect(open_disassembly_action, &QAction::triggered, this, [this] {
        main_views->tabBar()->show();

        if (auto* view = show_disassembly_view(); view && engine_->has_binary())
            view->set_binary(*engine_->binary());
    });
}

void user_interface_t::setup_toolbar() {
    QToolBar* toolbar = addToolBar("Toolbar");
    toolbar->setMovable(false);
    toolbar->setIconSize(QSize(16, 16));

    const auto add_tool = [this, toolbar](QStyle::StandardPixmap icon, const QString& text) {
        QAction* action = toolbar->addAction(style()->standardIcon(icon), text);
        connect(action, &QAction::triggered, this, [this, text] {
            statusBar()->showMessage(text, 1000);
        });
        
        return action;
    };

    add_tool(QStyle::SP_ArrowBack, "Back");
    add_tool(QStyle::SP_ArrowForward, "Forward");
}

void user_interface_t::setup_function_list() {
    functions_dock = new QDockWidget("Functions", this);
    functions_dock->setObjectName("functions_dock");
    functions_dock->setAllowedAreas(
        Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea
    );

    function_list = new QTreeWidget(functions_dock);
    function_list->setColumnCount(1);
    function_list->setHeaderLabels({"Name"});
    function_list->setAlternatingRowColors(true);
    function_list->setSortingEnabled(true);

    functions_dock->setWidget(function_list);
    functions_dock->hide();

    addDockWidget(Qt::LeftDockWidgetArea, functions_dock);
    resizeDocks({functions_dock}, {width() / 5}, Qt::Horizontal);
}

void user_interface_t::setup_main_views() {
    main_views = new QTabWidget(this);
    main_views->setObjectName("main_tabs");
    main_views->setDocumentMode(true);
    main_views->setMovable(true);
    main_views->setTabsClosable(true);

    auto* label = new QLabel("open a file to disassemble it", main_views);
    label->setObjectName("intro_label");
    label->setAlignment(Qt::AlignCenter);
    main_views->addTab(label, "decompatty");
    main_views->tabBar()->setExpanding(true);
    main_views->tabBar()->hide();

    setCentralWidget(main_views);
}

void user_interface_t::setup_output() {
    auto* dock = new QDockWidget("Output", this);
    dock->setObjectName("output_dock");
    dock->setAllowedAreas(Qt::BottomDockWidgetArea);

    auto* container = new QWidget(dock);
    auto* layout = new QVBoxLayout(container);

    output = new QPlainTextEdit(container);
    output->setObjectName("output_view");
    output->setReadOnly(true);
    output->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    output->setMaximumBlockCount(5000);

    input = new QLineEdit(container);
    input->setObjectName("input_box");
    connect(input, &QLineEdit::returnPressed, this, &user_interface_t::execute_command);
    
    layout->addWidget(output);
    layout->addWidget(input);

    dock->setWidget(container);
    addDockWidget(Qt::BottomDockWidgetArea, dock);

    resizeDocks({dock}, {height() / 3}, Qt::Vertical);
}

void user_interface_t::log(const QString& message) {
    if (!output)
        return;

    output->appendPlainText(message);
}

void user_interface_t::apply_theme() {
    std::string sheet = read_theme("themes/base/theme.css");
    sheet += read_theme("themes/dark/theme.css");

    if (sheet.empty())
        return;

    setStyleSheet(QString::fromStdString(sheet));
}
