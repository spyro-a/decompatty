#include <core/app.hpp>

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFileInfo>

#include <ui/user_interface.hpp>

app_t::app_t(int& argc, char* argv[])
    : qt_app(argc, argv),
      ui(std::make_unique<user_interface_t>()) {}

app_t::~app_t() = default;

int app_t::run() {
    if (startup_failed_)
        return 1;

    ui->show();

    return qt_app.exec();
}

bool app_t::setup(const char* app_name, int width, int height) {
    QCommandLineParser parser;
    parser.setApplicationDescription("Mach-O/ELF/PE binary analysis workbench");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument("file", "Binary to open on startup.");
    parser.process(qt_app);

    const QStringList positional = parser.positionalArguments();
    if (!positional.isEmpty())
        startup_path_ = positional.first();

    ui->set_engine(&analysis);

    if (!ui->setup(app_name, width, height))
        return false;

    analysis.discover_archs(QCoreApplication::applicationDirPath().toStdString() + "/arch");

    if (!startup_path_.isEmpty() && !ui->open_path(startup_path_)) {
        qCritical("decompatty: cannot open %s", QFileInfo(startup_path_).absoluteFilePath()
                                                .toLocal8Bit().constData());
        startup_failed_ = true;
    }

    return true;
}
