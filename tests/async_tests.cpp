#include <core/analysis_engine.hpp>
#include <format/macho/macho_file.hpp>
#include <ui/user_interface.hpp>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QMenu>
#include <QInputDialog>
#include <QLabel>
#include <QDir>
#include <QToolButton>
#include <QTableView>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>

#include <atomic>
#include <chrono>
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

QByteArray fixture(std::size_t count, bool arm = false, bool functions = false) {
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
    const std::size_t text_offset = functions ? 200 : 184;
    QByteArray starts;
    auto delta = [&](std::uint64_t value) {
        do {
            auto byte = static_cast<char>(value & 0x7F);
            value >>= 7;
            starts.append(value ? byte | 0x80 : byte);
        } while (value);
    };
    if (functions) {
        delta(text_offset);
        for (std::size_t i = 4000; i < count; i += 4000)
            delta(4000 * (arm ? 4 : 7));
        starts.append(char{0});
    }
    const auto file_size = text_size + text_offset + starts.size();
    number(0xFEEDFACF, 4);
    number(arm ? 0x0100000C : 0x01000007, 4);
    number(3, 4);
    number(2, 4);
    number(functions ? 2 : 1, 4);
    number(functions ? 168 : 152, 4);
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
    number(0x1000 + text_offset, 8);
    number(text_size, 8);
    number(text_offset, 4);
    for (int i = 0; i < 7; ++i)
        number(0, 4);
    if (functions) {
        number(0x26, 4);
        number(16, 4);
        number(text_offset + text_size, 4);
        number(starts.size(), 4);
    }
    check(result.size() == text_offset);
    // Seven-byte instructions deliberately cross 16 KiB batch boundaries.
    const char instruction[]{0x48, char(0x8b), 0x05, 0x01, 0, 0, 0};
    for (std::size_t i = 0; i < count; ++i) {
        if (arm)
            number(0xD503201F, 4); // nop
        else
            result.append(instruction, sizeof(instruction));
    }
    result.append(starts);
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

class listing_binary_t : public binary_file_t {
public:
    listing_binary_t() : binary_file_t(std::vector<std::byte>(16, std::byte{0x90})) {}
    const std::vector<symbol_t>& symbols() const override { return symbols_; }
    const std::vector<string_t>& strings() const override { return strings_; }

private:
    void parse_header() override {}
    std::vector<symbol_t> symbols_{{"_main", 0x1000, 0x0F, 1, 0}, {"_cleanup", 0x1002, 0x0F, 1, 0}};
    std::vector<string_t> strings_;
};

void check_listing() {
    auto binary = std::make_shared<listing_binary_t>();
    disassembly_model_t model(binary);
    auto first = std::make_shared<std::vector<instruction_t>>();
    first->push_back({0x1000, "push", "rbp", 0, 1, 0});
    first->push_back({0x1001, "mov", "rbp, rsp", 1, 1, 0});
    model.append(first);
    auto second = std::make_shared<std::vector<instruction_t>>();
    second->push_back({0x1002, "sub", "rsp, 0x20", 2, 1, 0});
    second->push_back({0x1003, "call", "0x1030", 3, 1, DECOMPATTY_INSTR_BRANCH});
    second->push_back({0x1004, "ret", "", 4, 1, DECOMPATTY_INSTR_BRANCH});
    model.append(second);
    check(model.rowCount() == 7);
    check(model.data(model.index(0, 0), disassembly_model_t::label_role).toString() == "_main:");
    check(model.data(model.index(3, 0), disassembly_model_t::label_role).toString() == "_cleanup:");
    check(model.row_for_address(0x1000) == 1);
    check(model.row_for_address(0x1002) == 4);
    check(model.row_for_address(0x1004) == 6);
    check(model.row_for_address(0xFFFF) == -1);
    check(model.data(model.index(5, 2)).toString() == "call");
    check(model.data(model.index(1, 0), Qt::AccessibleTextRole).toString().contains("push"));

    disassembly_view_t view(binary);
    view.append(first);
    view.append(second);
    view.resize(1100, 400);
    view.show();
    auto* table = view.findChild<QTableView*>();
    auto* bytes = view.findChild<QCheckBox*>("opcode_bytes");
    check(bytes && !bytes->isChecked());
    QCoreApplication::processEvents();
    const auto without_bytes = view.grab().toImage();
    bytes->setChecked(true);
    QCoreApplication::processEvents();
    check(without_bytes != view.grab().toImage());
    check(table->model()->rowCount() == 7);
    QTimer::singleShot(0, [] {
        auto* dialog = qobject_cast<QInputDialog*>(QApplication::activeModalWidget());
        check(dialog);
        dialog->setTextValue("1004");
        dialog->accept();
    });
    view.findChild<QToolButton*>()->click();
    check(table->currentIndex().data(Qt::UserRole).toULongLong() == 0x1004);
    if (qEnvironmentVariableIsSet("DECOMPATTY_LISTING_SCREENSHOT"))
        check(view.grab().save(qEnvironmentVariable("DECOMPATTY_LISTING_SCREENSHOT")));
}

std::atomic<int> active_decoders = 0;
std::atomic<int> peak_decoders = 0;
std::atomic<bool> fail_decoder = false;
decompatty_status (*original_disassemble)(void*, const decompatty_section*, const decompatty_host*) = nullptr;

decompatty_status observed_disassemble(void* context, const decompatty_section* section, const decompatty_host* host) {
    const auto active = ++active_decoders;
    auto peak = peak_decoders.load();
    while (active > peak && !peak_decoders.compare_exchange_weak(peak, active)) {}
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const auto result = fail_decoder ? DECOMPATTY_ERR_INTERNAL : original_disassemble(context, section, host);
    --active_decoders;
    return result;
}

void check_parallel(analysis_engine_t& engine, bool arm) {
    const auto* original = engine.arch_loader().find(arm ? DECOMPATTY_CPU_ARM64 : DECOMPATTY_CPU_X86_64,
                                                    DECOMPATTY_FORMAT_MACHO);
    check(original);
    auto api = *original;
    original_disassemble = api.disassemble;
    api.disassemble = observed_disassemble;
    const auto raw = fixture(40000, arm, !arm);
    const auto* begin = reinterpret_cast<const std::byte*>(raw.constData());
    auto resolver = [](void* context, std::uint32_t, std::uint32_t) {
        return static_cast<const decompatty_arch_api*>(context);
    };
    macho_file_t file(std::vector<std::byte>(begin, begin + raw.size()), {}, resolver, &api, 0, true);
    check(file.valid());
    std::vector<instruction_t> serial;
    check(file.disassemble([&](instruction_batch_t batch) {
        serial.insert(serial.end(), batch->begin(), batch->end());
        return true;
    }, {}, {1, 4096}));
    check(serial.size() == 40000);
    peak_decoders = 0;
    std::size_t index = 0;
    check(file.disassemble([&](instruction_batch_t batch) {
        for (const auto& instruction : *batch) {
            check(index < serial.size());
            const auto& expected = serial[index++];
            check(instruction.address == expected.address && instruction.file_offset == expected.file_offset &&
                  instruction.length == expected.length && instruction.mnemonic == expected.mnemonic &&
                  instruction.operands == expected.operands && instruction.flags == expected.flags);
        }
        return true;
    }, {}, {4, 4096}));
    check(index == serial.size() && peak_decoders >= 2 && peak_decoders <= 4);
    index = 0;
    check(file.disassemble([&](instruction_batch_t batch) {
        for (const auto& instruction : *batch) {
            const auto& expected = serial[index++];
            check(instruction.address == expected.address && instruction.file_offset == expected.file_offset &&
                  instruction.length == expected.length && instruction.mnemonic == expected.mnemonic &&
                  instruction.operands == expected.operands);
        }
        return true;
    }, {}, {4, 65536}));
    check(index == serial.size());
    fail_decoder = true;
    check(!file.disassemble([](instruction_batch_t) { return true; }, {}, {4, 4096}));
    fail_decoder = false;
    check(!file.disassemble([](instruction_batch_t) { return false; }, {}, {4, 4096}));
    std::stop_source cancelled;
    check(!file.disassemble([&](instruction_batch_t) {
        cancelled.request_stop();
        return true;
    }, cancelled.get_token(), {4, 4096}));
    check(active_decoders == 0);
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QTemporaryDir preferences;
    check(preferences.isValid());
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, preferences.path());
    check_listing();
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
    check_parallel(engine, false);
    check_parallel(engine, true);

    auto* settings_action = ui.findChild<QAction*>("threading_settings_action");
    check(settings_action);
    QTimer::singleShot(0, [&] {
        auto* dialog = QApplication::activeModalWidget();
        check(dialog && dialog->objectName() == "threading_settings");
        auto* parallel = dialog->findChild<QCheckBox*>("parallel_disassembly");
        auto* workers = dialog->findChild<QSpinBox*>("decoder_workers");
        check(!parallel->isChecked() && !workers->isEnabled());
        parallel->setChecked(true);
        check(workers->isEnabled());
        workers->setValue(4);
        auto* batch = dialog->findChild<QComboBox*>("disassembly_batch_size");
        batch->setCurrentIndex(batch->findData(4096));
        dialog->findChild<QSpinBox*>("queued_disassembly_batches")->setValue(1);
        if (qEnvironmentVariableIsSet("DECOMPATTY_THREADING_SCREENSHOT"))
            check(dialog->grab().save(qEnvironmentVariable("DECOMPATTY_THREADING_SCREENSHOT")));
        dialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
    });
    settings_action->trigger();
    check(engine.threading_settings().parallel && engine.threading_settings().workers == 4);
    check(engine.threading_settings().batch_bytes == 4096 && engine.threading_settings().queued_batches == 1);
    {
        analysis_engine_t restored;
        check(restored.threading_settings().workers == 4 && restored.threading_settings().parallel);
    }
    QTimer::singleShot(0, [&] {
        auto* dialog = QApplication::activeModalWidget();
        auto* buttons = dialog->findChild<QDialogButtonBox*>();
        buttons->button(QDialogButtonBox::RestoreDefaults)->click();
        check(!dialog->findChild<QCheckBox*>("parallel_disassembly")->isChecked());
        buttons->button(QDialogButtonBox::Cancel)->click();
    });
    settings_action->trigger();
    check(engine.threading_settings().workers == 4 && engine.threading_settings().parallel);

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
        check(table && table->model()->rowCount() >= static_cast<int>(engine.instruction_count()));
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
            check(table && table->model()->rowCount() >= static_cast<int>(engine.instruction_count()));
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

    const auto rows_before_theme = table->model()->rowCount();
    const std::vector<std::tuple<QString, QString, QString>> palettes{
        {"dark", "#89B8F5", "#1E1E1E"}, {"light", "#135B94", "#FFFFFF"},
        {"nord", "#81A1C1", "#2E3440"}, {"dracula", "#BD93F9", "#282A36"},
        {"gruvbox", "#83A598", "#282828"}, {"solarized", "#6CA7DF", "#002B36"}
    };
    for (const auto& [name, registers, background] : palettes) {
        auto* action = ui.findChild<QAction*>("theme_" + name);
        check(action);
        action->trigger();
        QCoreApplication::processEvents();
        check(ui.theme_name() == name && action->isChecked());
        auto* listing = ui.views().at("disassembly_view");
        check(listing->property("registerColor").value<QColor>() == QColor(registers));
        check(table->palette().color(QPalette::Base) == QColor(background));
        check(table->styleSheet().isEmpty());
        check(table->model()->rowCount() == rows_before_theme);
        if (qEnvironmentVariableIsSet("DECOMPATTY_THEME_SCREENSHOTS"))
            check(ui.grab().save(qEnvironmentVariable("DECOMPATTY_THEME_SCREENSHOTS") + '/' + name + ".png"));
    }
    check(!ui.set_theme("missing-theme") && ui.theme_name() == "solarized");
    {
        user_interface_t saved_theme;
        check(saved_theme.setup("Theme persistence", 640, 480));
        check(saved_theme.set_theme("dracula"));
        check(saved_theme.close());
        user_interface_t restored_theme;
        check(restored_theme.setup("Theme persistence", 640, 480));
        check(restored_theme.theme_name() == "dracula");
        check(restored_theme.findChild<QAction*>("theme_dracula")->isChecked());
        QSettings preferences(QSettings::defaultFormat(), QSettings::UserScope, "decompatty", "decompatty");
        preferences.setValue("appearance/theme", "removed-theme");
        preferences.sync();
        user_interface_t missing_theme;
        check(missing_theme.setup("Missing theme", 640, 480));
        check(missing_theme.theme_name() == "dark");
        check(missing_theme.findChild<QAction*>("theme_dark")->isChecked());
        preferences.remove("appearance/theme");
        preferences.sync();
    }
    check(ui.set_theme("dark"));
    auto* title = ui.findChild<QLabel*>("app_title");
    check(title && title->text() == ui.windowTitle());
    for (const int width : {1100, 800}) {
        ui.resize(width, 600);
        QCoreApplication::processEvents();
        const auto center = title->mapTo(&ui, title->rect().center()).x();
        check(std::abs(center - ui.rect().center().x()) <= 3);
    }

    // Applying preferences during a load changes only the next job's snapshot.
    const auto with_functions = directory.filePath("functions.macho");
    write_file(with_functions, fixture(40000, false, true));
    const auto saved_settings = engine.threading_settings();
    QMetaObject::Connection changed_settings;
    changed_settings = QObject::connect(&engine, &analysis_engine_t::binary_ready, [&] {
        check(engine.set_threading_settings({false, 1, 65536, 8}));
        QObject::disconnect(changed_settings);
    });
    const auto check_batch_size = QObject::connect(&engine, &analysis_engine_t::instructions_ready,
        [&](instruction_batch_t batch) {
            check(!engine.threading_settings().parallel);
            check(batch->size() < 1000); // This job still uses the original 4 KiB batches.
        });
    finished = false;
    check(ui.open_path(with_functions));
    wait_until([&] { return finished; });
    check(success && engine.instruction_count() == 40000);
    QObject::disconnect(check_batch_size);
    check(engine.set_threading_settings(saved_settings));

    // Let the worker fill its bounded queue, then replace the job before delivering it.
    finished = false;
    check(ui.open_path(large));
    QThread::msleep(100);
    check(ui.open_path(small));
    wait_until([&] { return finished; });
    check(success && engine.instruction_count() == 3);
    check(title->text() == ui.windowTitle() && title->text().contains("small.macho"));
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
    std::cout << "Async streaming, parallel decoding, settings, cancellation and shutdown checks passed\n";
}
