#pragma once

#include <QtCore/qstring.h>

#include <concepts>
#include <cstddef>
#include <optional>
#include <type_traits>
#include <vector>

namespace utils {
    std::optional<std::vector<std::byte>> load_file(const char* path);

    inline QString hex(std::byte value, int width = 2) {
        return QStringLiteral("%1").arg(
            std::to_integer<unsigned int>(value),
            width,
            16,
            QChar('0')
        ).toUpper();
    }

    template <typename T>
        requires std::integral<T>
    QString hex(T value, int width = sizeof(T) * 2) {
        return QStringLiteral("%1").arg(
            static_cast<typename std::make_unsigned<T>::type>(value),
            width,
            16,
            QChar('0')
        ).toUpper();
    }
}
