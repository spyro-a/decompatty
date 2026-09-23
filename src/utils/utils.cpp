#include <fstream>

#include <QtCore/qstring.h>

#include <utils/utils.hpp>

std::optional<std::vector<std::byte>> utils::load_file(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file)
        return std::nullopt;

    const auto size = file.tellg();

    if (size <= 0)
        return std::nullopt;

    file.seekg(0);

    std::vector<std::byte> data(static_cast<std::size_t>(size));

    file.read(
        reinterpret_cast<char*>(data.data()),
        size
    );

    if (!file)
        return std::nullopt;

    return data;
}
