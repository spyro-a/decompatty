#pragma once

#include <cstddef>
#include <optional>
#include <vector>

namespace utils {
    std::optional<std::vector<std::byte>> load_file(const char* path);
}
