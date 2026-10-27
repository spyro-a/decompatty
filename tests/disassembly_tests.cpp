#include <format/macho/macho_file.hpp>
#include <ui/views/strings_view.hpp>

#include <QApplication>
#include <QTreeWidget>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <iostream>
#include <source_location>

void check(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::cerr << "Disassembly check failed at line " << location.line() << '\n';
        std::exit(1);
    }
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    const std::string raw("a\nb\rc\td\\e\0\x1b", 11);
    const std::vector<string_t> strings{{raw, 0x1234, 0}, {"caf\xc3\xa9", 0x1235, 11}};
    strings_view_t view(strings);
    auto* tree = view.findChild<QTreeWidget*>();
    check(tree && tree->topLevelItemCount() == 2);
    tree->sortItems(0, Qt::AscendingOrder);
    check(tree->topLevelItem(0)->text(2) == QStringLiteral("a\\nb\\rc\\td\\\\e\\0\\x1b"));
    check(tree->topLevelItem(0)->text(1) == QString::number(raw.size()));
    check(tree->topLevelItem(1)->text(2) == QString::fromUtf8("caf\xc3\xa9"));
    check(strings[0].value == raw);

    check(argc >= 2);
    void* module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module)
        std::cerr << dlerror() << '\n';
    check(module);
    auto query = reinterpret_cast<const decompatty_arch_api* (*)()>(dlsym(module, "decompatty_arch_api_v1"));
    check(query);
    const auto* api = query();
    void* context = nullptr;
    check(api->create(nullptr, &context) == DECOMPATTY_OK && context);

    const std::uint8_t bytes[]{0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20,
                               0xe8, 0, 0, 0, 0, 0x75, 0x02, 0xc3, 0x0f};
    decompatty_section section{bytes, sizeof(bytes), 0x1000, 0, "__text"};
    check(api->disassemble(context, &section, nullptr) == DECOMPATTY_OK);
    check(api->instruction_count(context) == 7);
    const char* expected[]{"push", "mov", "sub", "call", "jne", "ret", ".byte"};
    const std::uint32_t offsets[]{0, 1, 4, 8, 13, 15, 16};
    for (std::size_t i = 0; i < 7; ++i) {
        const auto* instruction = api->instruction_at(context, i);
        check(instruction && instruction->address == 0x1000 + offsets[i]);
        check(instruction->section_offset == offsets[i]);
        check(std::strcmp(api->string_at(context, instruction->mnemonic_offset), expected[i]) == 0);
        check(instruction->flags == ((i >= 3 && i <= 5) ? DECOMPATTY_INSTR_BRANCH : 0));
    }
    check(!api->instruction_at(context, 7));
    check(std::strcmp(api->string_at(context, api->instruction_at(context, 1)->operands_offset), "rbp, rsp") == 0);

    // A second call replaces results and can decode a truncated tail without reading past it.
    section.data = bytes + 16;
    section.length = 1;
    check(api->disassemble(context, &section, nullptr) == DECOMPATTY_OK);
    check(api->instruction_count(context) == 1);
    check(api->disassemble(nullptr, &section, nullptr) == DECOMPATTY_ERR_INVAL);
    api->destroy(context);

    for (int i = 2; i < argc; ++i) {
        auto file = open_binary(argv[i]);
        check(file && file->architecture() == cpu_type_t::x86_64);
        const auto& macho = static_cast<const macho_file_t&>(*file);
        bool found = false;
        for (const auto& text : macho.sections()) {
            if (text.section_name != "__text" || text.data.empty())
                continue;
            found = true;
            check(api->create(nullptr, &context) == DECOMPATTY_OK);
            section.data = reinterpret_cast<const std::uint8_t*>(text.data.data());
            section.length = std::min<std::size_t>(text.data.size(), 65536);
            section.address = text.address;
            check(api->disassemble(context, &section, nullptr) == DECOMPATTY_OK);
            std::size_t covered = 0;
            for (std::size_t j = 0; j < api->instruction_count(context); ++j) {
                const auto* instruction = api->instruction_at(context, j);
                check(instruction && instruction->section_offset == covered);
                covered += instruction->length;
            }
            check(covered == section.length);
            std::cout << argv[i] << ": " << api->instruction_count(context) << " instructions/data rows\n";
            api->destroy(context);
        }
        check(found);
    }
    // Exercise the same resolver and parser path used by the application.
    if (argc > 2) {
        auto resolver = [](void* context, std::uint32_t cpu, std::uint32_t) -> const decompatty_arch_api* {
            const auto* api = static_cast<const decompatty_arch_api*>(context);
            return cpu == api->cpu ? api : nullptr;
        };
        auto file = open_binary(argv[2], {}, resolver, const_cast<decompatty_arch_api*>(api));
        check(file && !file->instructions().empty());
        for (const auto& instruction : file->instructions()) {
            check(instruction.file_offset < file->size());
            check(instruction.length <= file->size() - instruction.file_offset);
        }
    }
    dlclose(module);
    std::cout << "Strings and disassembly checks passed\n";
}
