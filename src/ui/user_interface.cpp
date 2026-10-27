#include "ui/views/hex_view.hpp"
#include <QFileDialog>
#include <QCloseEvent>
#include <QSettings>
#include <QActionGroup>
#include <QCoreApplication>
#include <QDir>
#include <QHBoxLayout>
#include <QToolButton>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QStatusBar>
#include <QMenuBar>
#include <QToolBar>
#include <QLabel>

#include <core/analysis_engine.hpp>

#include <ui/user_interface.hpp>

#include <utils/utils.hpp>

#include <algorithm>
#include <string>

std::string read_theme(const char* path) {
    const auto data = utils::load_file(path);

    if (!data)
        return {};

    return std::string(
        reinterpret_cast<const char*>(data->data()),
        data->size()
    );
}

user_interface_t::user_interface_t(QWidget* parent) : QMainWindow(parent) {
    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, &user_interface_t::save_theme);
}

void user_interface_t::closeEvent(QCloseEvent* event) {
    QMainWindow::closeEvent(event);
    if (event->isAccepted())
        save_theme();
}

void user_interface_t::save_theme() {
    if (styleSheet().isEmpty())
        return;
    QSettings saved(QSettings::defaultFormat(), QSettings::UserScope, "decompatty", "decompatty");
    saved.setValue("appearance/theme", theme_name_);
    saved.sync();
    if (saved.status() != QSettings::NoError)
        qWarning("decompatty: could not save theme preference");
}

void user_interface_t::set_engine(analysis_engine_t* engine) {
    if (engine_)
        disconnect(engine_, nullptr, this, nullptr);
    engine_ = engine;
    if (!engine_)
        return;

    connect(engine_, &analysis_engine_t::binary_ready, this, [this] {
        show_disassembly_view();
        statusBar()->showMessage("Disassembling...");
    });
    connect(engine_, &analysis_engine_t::instructions_ready, this, [this](instruction_batch_t batch) {
        if (disassembly_view_)
            disassembly_view_->append(std::move(batch));
        statusBar()->showMessage(QStringLiteral("Disassembling: %1 instructions").arg(engine_->instruction_count()));
    });
    connect(engine_, &analysis_engine_t::load_finished, this, [this](bool success) {
        if (success)
            statusBar()->showMessage(QStringLiteral("Ready: %1 instructions").arg(engine_->instruction_count()));
        else {
            statusBar()->showMessage("Analysis could not complete; see Output for details");
            log("analysis could not complete; the file may be invalid or its architecture unsupported");
        }
    });
}

bool user_interface_t::setup(const char* app_name, int width, int height) {
    setWindowTitle(app_name);
    connect(this, &QWidget::windowTitleChanged, this, [this](const QString& title) {
        if (app_title_)
            app_title_->setText(title);
    });
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

    open_path(path);
}

bool user_interface_t::open_path(const QString& path) {
    if (!engine_)
        return false;

    if (!QFile::exists(path)) {
        statusBar()->showMessage("no such file: " + path);
        return false;
    }

    engine_->set_logger([this](const std::string& message) {
        log(QString::fromStdString(message));
    });

    // Remove views tied to the previous file before replacing its data.
    for (auto* widget : {static_cast<QWidget*>(disassembly_view_), static_cast<QWidget*>(strings_view_),
                         static_cast<QWidget*>(hex_view_)}) {
        if (widget)
            close_tab(main_views->indexOf(widget));
    }
    hex_view_ = nullptr;

    if (!engine_->load(path.toLocal8Bit().constData()))
        return false;

    setWindowTitle(QStringLiteral("decompatty - %1").arg(QFileInfo(path).fileName()));
    statusBar()->showMessage("Loading: " + path);
    return true;
}

disassembly_view_t* user_interface_t::show_disassembly_view() {
    if (disassembly_view_)
        return disassembly_view_;

    if (!engine_ || !engine_->has_binary())
        return nullptr;

    disassembly_view_ = new disassembly_view_t(engine_->shared_binary(), this);
    for (const auto& batch : engine_->batches())
        disassembly_view_->append(batch);
    disassembly_view_->setObjectName("disassembly_view");

    main_views->addTab(disassembly_view_, "Disassembly");
    main_views->setCurrentWidget(disassembly_view_);
    main_views->tabBar()->show();

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

hex_view_t* user_interface_t::show_hex_view() {
    if (hex_view_)
        return hex_view_;

    if (!engine_ || !engine_->has_binary())
        return nullptr;

    hex_view_ = new hex_view_t(engine_->binary()->image_base(), engine_->binary()->data(), this);
    hex_view_->setObjectName("hex_view");

    main_views->addTab(hex_view_, "Hex");
    main_views->setCurrentWidget(hex_view_);
    main_views->tabBar()->show();

    views_["hex_view"] = hex_view_;

    return hex_view_;
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

bool user_interface_t::set_theme(const QString& name) {
    if (theme_directory_.isEmpty()) {
        theme_directory_ = QDir("themes").absolutePath();
        if (!QFile::exists(theme_directory_ + "/base/theme.css")) {
#ifdef DECOMPATTY_THEME_DIR
            theme_directory_ = QString::fromUtf8(DECOMPATTY_THEME_DIR);
#else
            theme_directory_ = QDir(QCoreApplication::applicationDirPath() + "/../themes").absolutePath();
#endif
        }
    }
    if (name.isEmpty() || name.contains('/') || name.contains('\\'))
        return false;
    const auto base = read_theme((theme_directory_ + "/base/theme.css").toLocal8Bit().constData());
    const auto theme = read_theme((theme_directory_ + '/' + name + "/theme.css").toLocal8Bit().constData());
    if (base.empty() || theme.empty())
        return false;

    // A theme may omit syntax overrides; fall back to the widget's palette then.
    for (auto* listing : findChildren<disassembly_view_t*>()) {
        for (const char* property : {"addressColor", "bytesColor", "labelColor", "mnemonicColor",
                                     "registerColor", "immediateColor", "controlColor"})
            listing->setProperty(property, QColor{});
    }
    theme_name_ = name;
    for (auto* action : findChildren<QAction*>())
        if (action->objectName().startsWith("theme_"))
            action->setChecked(action->objectName() == "theme_" + name);
    setStyleSheet(QString::fromStdString(base + "\n" + theme));
    for (auto* listing : findChildren<disassembly_view_t*>())
        listing->update();
    return true;
}

void user_interface_t::show_threading_settings() {
    if (!engine_)
        return;
    QDialog dialog(this);
    dialog.setObjectName("threading_settings");
    dialog.setWindowTitle("Threading settings");
    dialog.setMinimumWidth(460);
    auto* layout = new QVBoxLayout(&dialog);
    auto* description = new QLabel("Rendering stays on the main thread. Parsing and disassembly run in the background.", &dialog);
    description->setWordWrap(true);
    layout->addWidget(description);

    auto* parallel = new QCheckBox("Enable parallel disassembly", &dialog);
    parallel->setObjectName("parallel_disassembly");
    layout->addWidget(parallel);
    auto* form = new QFormLayout();
    auto* workers = new QSpinBox(&dialog);
    workers->setObjectName("decoder_workers");
    workers->setRange(0, 64);
    workers->setSpecialValueText("Automatic");
    workers->setToolTip("Automatic uses the logical CPU count minus one, with a minimum of 1 and a maximum of 64 decoder workers.");
    form->addRow("Decoder &workers", workers);
    auto* batch = new QComboBox(&dialog);
    batch->setObjectName("disassembly_batch_size");
    for (const auto bytes : {4096, 16384, 65536})
        batch->addItem(QStringLiteral("%1 KiB").arg(bytes / 1024), bytes);
    batch->setToolTip("Bytes decoded per update. Smaller batches display results sooner; larger batches reduce update overhead.");
    form->addRow("&Batch size", batch);
    auto* queued = new QSpinBox(&dialog);
    queued->setObjectName("queued_disassembly_batches");
    queued->setRange(1, 64);
    queued->setToolTip("Maximum pending UI updates. Lower limits reduce buffering when the UI is busy.");
    form->addRow("&Queued UI updates", queued);
    layout->addLayout(form);

    auto* note = new QLabel(QStringLiteral("%1 logical CPUs detected. ARM64 uses fixed-width ranges; x86_64 uses known function boundaries. A section uses one decoder when it cannot be split safely.\n\nSaved settings apply the next time you open a file.")
                               .arg(std::max(1u, std::thread::hardware_concurrency())), &dialog);
    note->setWordWrap(true);
    layout->addWidget(note);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel |
                                        QDialogButtonBox::RestoreDefaults, &dialog);
    layout->addWidget(buttons);
    const auto populate = [&](const threading_settings_t& settings) {
        parallel->setChecked(settings.parallel);
        workers->setValue(settings.workers);
        workers->setEnabled(settings.parallel);
        batch->setCurrentIndex(batch->findData(settings.batch_bytes));
        queued->setValue(settings.queued_batches);
    };
    populate(engine_->threading_settings());
    connect(parallel, &QCheckBox::toggled, workers, &QWidget::setEnabled);
    connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, &dialog,
            [&] { populate(threading_settings_t{}); });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        threading_settings_t settings{parallel->isChecked(), static_cast<unsigned>(workers->value()),
                                      batch->currentData().toUInt(), static_cast<unsigned>(queued->value())};
        if (!engine_->set_threading_settings(settings)) {
            QMessageBox::warning(&dialog, "Settings could not be saved", "Could not write the threading settings.");
            return;
        }
        dialog.accept();
        statusBar()->showMessage("Threading settings saved; applied the next time you open a file", 5000);
    });
    dialog.exec();
}

void user_interface_t::apply_theme() {
    QSettings saved(QSettings::defaultFormat(), QSettings::UserScope, "decompatty", "decompatty");
    const auto name = saved.value("appearance/theme", "dark").toString();
    if (!set_theme(name))
        set_theme("dark");
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

    auto* threading = edit->addAction("&Threading settings…");
    threading->setObjectName("threading_settings_action");
    connect(threading, &QAction::triggered, this, &user_interface_t::show_threading_settings);

    // view
    QMenu* open_view_menu = view->addMenu("&Open View");
    
    auto* theme_menu = view->addMenu("&Theme");
    auto* themes = new QActionGroup(this);
    themes->setExclusive(true);
    const QDir directory(theme_directory_);
    for (const auto& name : directory.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name)) {
        if (name == "base" || !QFile::exists(directory.filePath(name + "/theme.css")))
            continue;
        auto title = name;
        title.replace('-', ' ');
        title[0] = title[0].toUpper();
        auto* action = theme_menu->addAction(title);
        action->setObjectName("theme_" + name);
        action->setCheckable(true);
        action->setChecked(name == theme_name_);
        themes->addAction(action);
        connect(action, &QAction::triggered, this, [this, name, themes] {
            if (!set_theme(name)) {
                log("could not load theme: " + name);
                for (auto* entry : themes->actions())
                    entry->setChecked(entry->objectName() == "theme_" + theme_name_);
            }
        });
    }

    // layer 3
    QAction* open_disassembly_action = new QAction("&Disassembly View");
    open_view_menu->addAction(open_disassembly_action);
    connect(open_disassembly_action, &QAction::triggered, this, [this] {
        if (!show_disassembly_view())
            log("open a file before opening the disassembly view");
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

    auto* header = new QWidget(toolbar);
    header->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    auto* layout = new QHBoxLayout(header);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* navigation = new QWidget(header);
    auto* buttons = new QHBoxLayout(navigation);
    buttons->setContentsMargins(0, 0, 0, 0);
    for (const auto& tool : {std::pair{QStringLiteral("←"), QString("Back")},
                             std::pair{QStringLiteral("→"), QString("Forward")}}) {
        auto* button = new QToolButton(navigation);
        button->setText(tool.first);
        button->setToolTip(tool.second);
        button->setAccessibleName(tool.second);
        connect(button, &QToolButton::clicked, this, [this, text = tool.second] {
            statusBar()->showMessage(text, 1000);
        });
        buttons->addWidget(button);
    }
    navigation->setFixedWidth(navigation->sizeHint().width());
    layout->addWidget(navigation);

    app_title_ = new QLabel(windowTitle(), header);
    app_title_->setObjectName("app_title");
    app_title_->setAlignment(Qt::AlignCenter);
    app_title_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    layout->addWidget(app_title_, 1);

    // Equal space on the right keeps the title centered in the whole toolbar.
    auto* balance = new QWidget(header);
    balance->setFixedWidth(navigation->width());
    layout->addWidget(balance);
    toolbar->addWidget(header);
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

    else if (widget == hex_view_)
        hex_view_ = nullptr;

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