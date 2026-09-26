#include <core/arch_loader.hpp>

#include <dlfcn.h>

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>

constexpr const char* QUERY_SYMBOL = "decompatty_arch_api_v1";

using query_fn_t = const decompatty_arch_api* (*)(void);

bool has_module_extension(const std::filesystem::path& path) {
    static constexpr const char* EXTENSIONS[] = {".so", ".dylib", ".bundle", ".dll"};
    const std::string ext = path.extension().string();
    for (const char* entry : EXTENSIONS)
        if (ext == entry)
            return true;
    return false;
}

void arch_loader_t::log(const char* format, ...) const {
    if (!logger_)
        return;

    va_list args;
    va_start(args, format);

    char buffer[1024];
    std::vsnprintf(buffer, sizeof(buffer), format, args);

    va_end(args);

    logger_(buffer);
}

void arch_loader_t::discover(const std::string& dir) {
    namespace fs = std::filesystem;

    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        log("arch: no plugin directory at %s", dir.c_str());
        return;
    }

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file(ec) || !has_module_extension(entry.path()))
            continue;

        const auto path = entry.path().string();

        void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            const char* err = dlerror();
            log("arch: dlopen failed for %s: %s", path.c_str(), err ? err : "unknown");
            continue;
        }

        void* sym = dlsym(handle, QUERY_SYMBOL);
        if (!sym) {
            log("arch: %s exports no %s, skipping", path.c_str(), QUERY_SYMBOL);
            dlclose(handle);
            continue;
        }

        query_fn_t query = nullptr;
        std::memcpy(&query, &sym, sizeof(query));

        const decompatty_arch_api* api = query();
        if (!api) {
            log("arch: %s returned a null api table", path.c_str());
            dlclose(handle);
            continue;
        }

        if (api->abi_version != DECOMPATTY_ABI_VERSION) {
            log("arch: %s reports abi %u, host expects %u", path.c_str(), api->abi_version,
                DECOMPATTY_ABI_VERSION);
            dlclose(handle);
            continue;
        }

        if (api->struct_size < offsetof(decompatty_arch_api, string_at)) {
            log("arch: %s api table is truncated (struct_size %u)", path.c_str(),
                api->struct_size);
            dlclose(handle);
            continue;
        }

        if (!api->name) {
            log("arch: %s has no name", path.c_str());
            dlclose(handle);
            continue;
        }

        plugins_.push_back({handle, api});
        log("arch: loaded %s (cpu 0x%02X, formats 0x%02X)", api->name, api->cpu, api->formats);
    }

    if (ec)
        log("arch: error walking %s: %s", dir.c_str(), ec.message().c_str());
}

const decompatty_arch_api* arch_loader_t::find(std::uint32_t cpu, std::uint32_t format) const {
    for (const auto& plugin : plugins_) {
        if (plugin.api->cpu == cpu && (plugin.api->formats & format))
            return plugin.api;
    }
    return nullptr;
}
