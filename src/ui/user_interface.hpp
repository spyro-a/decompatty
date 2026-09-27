#pragma once

#include <ui/views/disassembly_view.hpp>
#include <ui/views/functions_view.hpp>
#include <ui/views/hex_view.hpp>
#include <ui/views/output_view.hpp>
#include <ui/views/strings_view.hpp>

#include <QMainWindow>

class analysis_engine_t;

class user_interface_t : public QMainWindow {
    Q_OBJECT
public:
    explicit user_interface_t(QWidget* parent = nullptr);

    inline void set_engine(analysis_engine_t* engine) noexcept { engine_ = engine; }
    bool setup(const char* app_name, int width, int height);
    std::unordered_map<QString, QWidget*>& views();

    void open_file();
    bool open_path(const QString& path);
    void execute_command(const QString& command);
    void close_tab(int index);

private:
    disassembly_view_t* show_disassembly_view();
    functions_view_t* show_functions_view();
    hex_view_t* show_hex_view();
    strings_view_t* show_strings_view();
    output_view_t* show_output_view();

    void apply_theme();
    void setup_ui();
    void setup_menus();
    void setup_toolbar();
    void setup_main_views();

    void log(const QString& message);


    QTabWidget* main_views = nullptr;

    std::unordered_map<QString, QWidget*> views_;

    disassembly_view_t* disassembly_view_ = nullptr;
    functions_view_t* functions_view_ = nullptr;
    hex_view_t* hex_view_ = nullptr;
    output_view_t* output_view_ = nullptr;
    strings_view_t* strings_view_ = nullptr;

    // data source
    analysis_engine_t* engine_ = nullptr;
};
