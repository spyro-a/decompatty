#pragma once

#include <QMainWindow>

class QDockWidget;
class QPlainTextEdit;
class QTabWidget;
class QTreeWidget;
class QString;
class QLineEdit;

class analysis_engine_t;
class disassembly_view_t;

class user_interface_t : public QMainWindow {
    Q_OBJECT
public:
    explicit user_interface_t(QWidget* parent = nullptr);

    inline void set_engine(analysis_engine_t* engine) noexcept { engine_ = engine; }

    bool setup(const char* app_name, int width, int height);

    std::unordered_map<QString, QWidget*>& views();

private slots:
    void open_file();

    QWidget* add_view(const QString& title, const QString& id);

    void execute_command();

private:
    disassembly_view_t* show_disassembly_view();

    void setup_ui();
    void setup_menus();
    void setup_toolbar();
    void setup_function_list();
    void setup_main_views();
    void setup_output();

    void log(const QString& message);

    void apply_theme();

    QTabWidget* main_views = nullptr;
    QDockWidget* functions_dock = nullptr;
    QTreeWidget* function_list = nullptr;
    QLineEdit* input = nullptr;
    QPlainTextEdit* output = nullptr;

    std::unordered_map<QString, QWidget*> views_;

    disassembly_view_t* disassembly_view_ = nullptr;

    analysis_engine_t* engine_ = nullptr;
};
