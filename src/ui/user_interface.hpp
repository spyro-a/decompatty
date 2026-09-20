#pragma once

#include <QMainWindow>

class QDockWidget;
class QPlainTextEdit;
class QTabWidget;
class QTreeWidget;
class QString;
class QLineEdit;

class analysis_engine_t;

class user_interface_t : public QMainWindow {
    Q_OBJECT
public:
    explicit user_interface_t(QWidget* parent = nullptr);

    inline void set_engine(analysis_engine_t* engine) noexcept { engine_ = engine; }

    bool setup(const char* app_name, int width, int height);

    std::unordered_map<QString, QPlainTextEdit*>& views();

private slots:
    void open_file();

    QPlainTextEdit* add_view(const QString& title, const QString& text);

    void execute_command();

private:
    void setup_ui();
    void setup_menus();
    void setup_toolbar();
    void setup_function_list();
    void setup_main_views();
    void setup_output();

    void log(const QString& message);

    void apply_theme();

    QTabWidget* main_views = nullptr;
    QTreeWidget* function_list = nullptr;
    QLineEdit* input = nullptr;
    QPlainTextEdit* output = nullptr;

    std::unordered_map<QString, QPlainTextEdit*> views_;

    analysis_engine_t* engine_ = nullptr;
};
