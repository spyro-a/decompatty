#include "format/binary_file.hpp"
#include "ui/views/disassembly_view.hpp"
#include "ui/views/functions_view.hpp"
#include "ui/views/output_view.hpp"
#include "ui/views/strings_view.hpp"
#include <QtCore/qnamespace.h>
#include <QtCore/qobject.h>
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

    main_views->tabBar()->show();
    
    show_functions_view();

    setWindowTitle(QStringLiteral("decompatty - %1").arg(QFileInfo(path).fileName()));
    statusBar()->showMessage("Opened: " + path);
}

disassembly_view_t* user_interface_t::show_disassembly_view() {
    if (disassembly_view_)
        return disassembly_view_;

    disassembly_view_ = new disassembly_view_t(this);
    disassembly_view_->setObjectName("disassembly_view");

    main_views->addTab(disassembly_view_, "Disassembly");
    main_views->setCurrentWidget(disassembly_view_);

    views_["disassembly_view"] = disassembly_view_;

    return disassembly_view_;
}

functions_view_t* user_interface_t::show_functions_view() {
    if (functions_view_)
        return functions_view_;
    
    functions_view_ = new functions_view_t("Functions", this);
    functions_view_->setObjectName("functions_view");

    views_["functions_view"] = functions_view_;

    addDockWidget(Qt::LeftDockWidgetArea, functions_view_);

    return functions_view_;
}

strings_view_t* user_interface_t::show_strings_view() {
    if (strings_view_)
        return strings_view_;

    if (!engine_ || !engine_->has_binary())
        return nullptr;

    strings_view_ = new strings_view_t(engine_->binary()->strings(), this);
    strings_view_->setObjectName("strings_view");

    main_views->addTab(strings_view_, "Strings");
    main_views->setCurrentWidget(strings_view_);
    main_views->tabBar()->show();

    views_["strings_view"] = strings_view_;

    return strings_view_;
}

output_view_t* user_interface_t::show_output_view() {
    if (output_view_)
        return output_view_;

    output_view_ = new output_view_t("Output", this);
    output_view_->setObjectName("output_view");

    views_["output_view"] = output_view_;

    addDockWidget(Qt::BottomDockWidgetArea, output_view_);

    return output_view_;
}

void user_interface_t::execute_command(const QString& command) {
    output_view_->append("> " + command);
    output_view_->append(QStringLiteral("'%1' is undefined").arg(command));
}

void user_interface_t::setup_ui() {
    apply_theme();

    setDockOptions(QMainWindow::AnimatedDocks | QMainWindow::AllowNestedDocks | QMainWindow::AllowTabbedDocks);
    setCorner(Qt::BottomLeftCorner, Qt::BottomDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::BottomDockWidgetArea);

    setup_menus();
    setup_toolbar();
    setup_main_views();
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
        // TODO: implement
    });

    QAction* open_strings_action = new QAction("&Strings View");
    open_view_menu->addAction(open_strings_action);
    connect(open_strings_action, &QAction::triggered, this, [this] {
        if (!show_strings_view())
            log("open a file before opening the strings view");
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

void user_interface_t::setup_main_views() {
    main_views = new QTabWidget(this);
    main_views->setObjectName("main_tabs");
    main_views->setDocumentMode(true);
    main_views->setMovable(true);
    main_views->setTabsClosable(true);
    connect(main_views, &QTabWidget::tabCloseRequested, this, &user_interface_t::close_tab);

    auto* label = new QLabel("open a file to disassemble it", main_views);
    label->setObjectName("intro_label");
    label->setAlignment(Qt::AlignCenter);
    main_views->addTab(label, "decompatty");
    main_views->tabBar()->setExpanding(true);
    main_views->tabBar()->hide();

    setCentralWidget(main_views);

    show_output_view();

    connect(output_view_, &output_view_t::command_entered, this, &user_interface_t::execute_command);
}

void user_interface_t::close_tab(int index) {
    QWidget* widget = main_views->widget(index);
    if (!widget)
        return;

    main_views->removeTab(index);
    widget->deleteLater();

    views_.erase(widget->objectName());

    if (widget == disassembly_view_)
        disassembly_view_ = nullptr;

    else if (widget == strings_view_)
        strings_view_ = nullptr;

    else if (widget == output_view_)
        output_view_ = nullptr;

    if (main_views->count() == 0)
        main_views->tabBar()->hide();
}

void user_interface_t::log(const QString& message) {
    if (!output_view_)
        return;

    output_view_->append(message);
}

void user_interface_t::apply_theme() {
    std::string sheet = read_theme("themes/base/theme.css");
    sheet += read_theme("themes/dark/theme.css");

    if (sheet.empty())
        return;

    setStyleSheet(QString::fromStdString(sheet));
}
