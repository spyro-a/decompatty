#include <core/analysis_engine.hpp>
#include <ui/user_interface.hpp>

#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QMenu>
#include <QTableView>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <source_location>

void check(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::cerr << "Async check failed at line " << location.line() << '\n';
        std::exit(1);
    }
}

QByteArray fixture(std::size_t count, bool arm = false) {
    QByteArray result;
    auto number = [&](std::uint64_t value, std::size_t bytes) {
        for (std::size_t i = 0; i < bytes; ++i)
            result.append(static_cast<char>(value >> (8 * i)));
    };
    auto name = [&](const char* text) {
        QByteArray value(text);
        value.resize(16, '\0');
        result.append(value);
    };
    const auto text_size = count * (arm ? 4 : 7);
    const auto file_size = text_size + 184;
    number(0xFEEDFACF, 4);
    number(arm ? 0x0100000C : 0x01000007, 4);
    number(3, 4);
    number(2, 4);
    number(1, 4);
    number(152, 4);
    number(0, 4);
    number(0, 4);
    number(0x19, 4);
    number(152, 4);
    name("__TEXT");
    number(0x1000, 8);
    number(file_size, 8);
    number(0, 8);
    number(file_size, 8);
    number(7, 4);
    number(5, 4);
    number(1, 4);
    number(0, 4);
    name("__text");
    name("__TEXT");
    number(0x1000 + 184, 8);
    number(text_size, 8);
    number(184, 4);
    for (int i = 0; i < 7; ++i)
        number(0, 4);
    check(result.size() == 184);
    // Seven-byte instructions deliberately cross 16 KiB batch boundaries.
    const char instruction[]{0x48, char(0x8b), 0x05, 0x01, 0, 0, 0};
    for (std::size_t i = 0; i < count; ++i) {
        if (arm)
            number(0xD503201F, 4); // nop
        else
            result.append(instruction, sizeof(instruction));
    }
    return result;
}

void write_file(const QString& path, const QByteArray& data) {
    QFile file(path);
    check(file.open(QIODevice::WriteOnly));
    check(file.write(data) == data.size());
}

void wait_until(const std::function<bool()>& done) {
    QElapsedTimer elapsed;
    elapsed.start();
    while (!done() && elapsed.elapsed() < 20000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        QThread::msleep(1);
    }
    check(done());
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    check(argc >= 2);
    QTemporaryDir directory;
    check(directory.isValid());
    const auto large = directory.filePath("large.macho");
    const auto small = directory.filePath("small.macho");
    const auto invalid = directory.filePath("invalid");
    write_file(large, fixture(200000));
    write_file(small, fixture(3));
    write_file(invalid, QByteArray("invalid"));

    analysis_engine_t engine;
    engine.discover_archs(argv[1]);
    user_interface_t ui;
    ui.set_engine(&engine);
    check(ui.setup("Async test", 800, 600));
    ui.show();

    int heartbeats = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++heartbeats; });
    heartbeat.start(1);
    int batches = 0;
    bool finished = false;
    bool success = false;
    QObject::connect(&engine, &analysis_engine_t::instructions_ready, [&](instruction_batch_t batch) {
        check(QThread::currentThread() == app.thread());
        check(engine.loading() && !finished && !batch->empty());
        auto* table = ui.views().at("disassembly_view")->findChild<QTableView*>("disassembly_table");
        check(table && table->model()->rowCount() == static_cast<int>(engine.instruction_count()));
        ++batches;
        if (batches == 2) {
            ui.close_tab(ui.findChild<QTabWidget*>()->indexOf(table->parentWidget()));
            bool reopened = false;
            for (auto* menu : ui.findChildren<QMenu*>()) {
                for (auto* action : menu->actions()) {
                    if (action->text() == "&Disassembly View") {
                        action->trigger();
                        reopened = true;
                    }
                }
            }
            check(reopened);
            table = ui.views().at("disassembly_view")->findChild<QTableView*>("disassembly_table");
            check(table && table->model()->rowCount() == static_cast<int>(engine.instruction_count()));
        }
    });
    QObject::connect(&engine, &analysis_engine_t::load_finished, [&](bool result) {
        success = result;
        finished = true;
    });

    check(ui.open_path(large));
    check(!finished && engine.loading());
    wait_until([&] { return finished; });
    check(success && batches > 2 && heartbeats > 0);
    check(engine.instruction_count() == 200000);
    std::size_t offset = 184;
    for (const auto& batch : engine.batches()) {
        for (const auto& instruction : *batch) {
            check(instruction.file_offset == offset && instruction.length == 7);
            check(instruction.address == 0x1000 + offset && instruction.mnemonic == "mov");
            offset += 7;
        }
    }
    auto* table = ui.views().at("disassembly_view")->findChild<QTableView*>("disassembly_table");
    check(table->model()->data(table->model()->index(0, 1)).toString() == "48 8B 05 01 00 00 00");
    check(table->model()->data(table->model()->index(199999, 2)).toString() == "mov");

    if (qEnvironmentVariableIsSet("DECOMPATTY_TEST_SCREENSHOT"))
        check(ui.grab().save(qEnvironmentVariable("DECOMPATTY_TEST_SCREENSHOT")));

    // Let the worker fill its bounded queue, then replace the job before delivering it.
    finished = false;
    check(ui.open_path(large));
    QThread::msleep(100);
    check(ui.open_path(small));
    wait_until([&] { return finished; });
    check(success && engine.instruction_count() == 3);
    table = ui.views().at("disassembly_view")->findChild<QTableView*>("disassembly_table");
    check(table && table->model()->rowCount() == 3);
    table->sortByColumn(0, Qt::DescendingOrder);
    check(table->model()->data(table->model()->index(0, 0)).toString() == "0x10c6");
    table->sortByColumn(0, Qt::AscendingOrder);
    check(table->model()->data(table->model()->index(0, 0)).toString() == "0x10b8");

    // Closing and reopening the disassembly tab restores already received batches.
    ui.close_tab(ui.findChild<QTabWidget*>()->indexOf(table->parentWidget()));
    auto* replacement = new disassembly_view_t(engine.shared_binary());
    for (const auto& batch : engine.batches())
        replacement->append(batch);
    check(replacement->findChild<QTableView*>()->model()->rowCount() == 3);
    delete replacement;

    const auto arm = directory.filePath("arm.macho");
    write_file(arm, fixture(20000, true));
    finished = false;
    check(ui.open_path(arm));
    wait_until([&] { return finished; });
    check(success && engine.instruction_count() == 20000);
    for (const auto& batch : engine.batches())
        for (const auto& instruction : *batch)
            check(instruction.length == 4 && instruction.mnemonic == "nop");

    if (argc > 2) {
        const auto before = batches;
        finished = false;
        check(ui.open_path(QString::fromLocal8Bit(argv[2])));
        wait_until([&] { return finished; });
        check(success && batches > before + 1 && engine.instruction_count() > 0);
        std::cout << "Real binary: streamed " << engine.instruction_count() << " rows in " << batches - before << " batches\n";
    }

    finished = false;
    check(ui.open_path(invalid));
    wait_until([&] { return finished; });
    check(!success && !engine.has_binary());
    finished = false;
    check(ui.open_path(small));
    wait_until([&] { return finished; });
    check(success);

    // Shutdown must release a worker waiting for queue space without UI event processing.
    {
        analysis_engine_t closing;
        closing.discover_archs(argv[1]);
        check(closing.load(large.toLocal8Bit().constData()));
        QThread::msleep(100);
    }
    engine.cancel();
    std::cout << "Async streaming, UI heartbeat, batch boundaries, replacement, failure and shutdown checks passed\n";
}
