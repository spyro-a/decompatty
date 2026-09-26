#include <core/app.hpp>

#include <QCoreApplication>

#include <ui/user_interface.hpp>

app_t::app_t(int& argc, char* argv[])
    : qt_app(argc, argv),
      ui(std::make_unique<user_interface_t>()) {}

app_t::~app_t() = default;

int app_t::run() {
    ui->show();

    return qt_app.exec();
}

bool app_t::setup(const char* app_name, int width, int height) {
    ui->set_engine(&analysis);

    if (!ui->setup(app_name, width, height))
        return false;

    analysis.discover_archs(QCoreApplication::applicationDirPath().toStdString() + "/arch");
    return true;
}