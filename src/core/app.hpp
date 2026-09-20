#pragma once

#include <QApplication>
#include <memory>

#include <core/analysis_engine.hpp>

class user_interface_t;

class app_t {
public:
    app_t(int argc, char* argv[]);
    ~app_t();
    
    int run();
    bool setup(const char* app_name, int width, int height);

private:
    QApplication qt_app;
    std::unique_ptr<user_interface_t> ui;
    analysis_engine_t analysis;
};