#include <core/analysis_engine.hpp>

#include <utility>

bool analysis_engine_t::load(const char* path) {
    auto file = open_binary(path);

    if (!file)
        return false;

    binary_ = std::move(file);
    return true;
}