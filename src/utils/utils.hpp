#pragma once

#include <QtCore/qstring.h>

#include <cstddef>
#include <optional>
#include <vector>

namespace utils {
    std::optional<std::vector<std::byte>> load_file(const char* path);

    QString hex(std::byte value, int width = 8);
}
