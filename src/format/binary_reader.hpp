#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

#include <format/binary_format.hpp>

class binary_reader_t {
public:
    binary_reader_t() = default;
    explicit binary_reader_t(std::span<const std::byte> data);

    template <typename T>
    T read() {
        const T value = read_at<T>(offset);
        offset += sizeof(T);
        return value;
    }

    template <typename T>
    T peek() const {
        return read_at<T>(offset);
    }

    template <typename T>
    T read_at(std::size_t position) const {
        if (!can_read(position, sizeof(T)))
            throw std::out_of_range("binary_reader_t: read past end of data");

        T value{};

        if (endianness == endianness_t::little) {
            for (std::size_t i = 0; i < sizeof(T); ++i)
                value |= static_cast<T>(std::to_integer<std::uint8_t>(data[position + i])) << (i * 8);
        } else {
            for (std::size_t i = 0; i < sizeof(T); ++i)
                value |= static_cast<T>(std::to_integer<std::uint8_t>(data[position + i])) << ((sizeof(T) - 1 - i) * 8);
        }

        return value;
    }

    std::uint8_t u8();
    std::uint16_t u16();
    std::uint32_t u32();
    std::uint64_t u64();

    std::span<const std::byte> bytes(std::size_t n);
    std::string string(std::size_t n);

    std::uint32_t magic() const;

    void set_endianness(endianness_t endianness) noexcept;
    endianness_t get_endianness() const noexcept;

    void seek(std::size_t offset) noexcept;
    void skip(std::size_t n);
    std::size_t tell() const noexcept;
    std::size_t remaining() const noexcept;

    bool can_read(std::size_t n) const noexcept;
    bool can_read(std::size_t position, std::size_t n) const noexcept;

private:
    endianness_t endianness = endianness_t::little;

    std::span<const std::byte> data;
    std::size_t offset = 0;
};
