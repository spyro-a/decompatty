#include <core/analysis_engine.hpp>

#include <utility>

const decompatty_arch_api* resolve_arch(void* ctx, std::uint32_t cpu, std::uint32_t format) {
    return static_cast<analysis_engine_t*>(ctx)->arch_loader().find(cpu, format);
}

bool analysis_engine_t::load(const char* path) {
    auto file = open_binary(path, logger_, resolve_arch, this);

    if (!file)
        return false;

    binary_ = std::move(file);
    return true;
}

void analysis_engine_t::discover_archs(const std::string& dir) {
    arch_.discover(dir);
}
