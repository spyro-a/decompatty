#include <format/binary_reader.hpp>

binary_reader_t::binary_reader_t(std::span<const std::byte> data) : data(data) {}

std::uint8_t binary_reader_t::u8() { return read<std::uint8_t>(); }
std::uint16_t binary_reader_t::u16() { return read<std::uint16_t>(); }
std::uint32_t binary_reader_t::u32() { return read<std::uint32_t>(); }
std::uint64_t binary_reader_t::u64() { return read<std::uint64_t>(); }

std::span<const std::byte> binary_reader_t::bytes(std::size_t n) {
    if (!can_read(n))
        throw std::out_of_range("binary_reader_t: read past end of data");

    const auto result = data.subspan(offset, n);
    offset += n;
    return result;
}

std::string binary_reader_t::string(std::size_t n) {
    const auto data = bytes(n);

    const auto* begin = reinterpret_cast<const char*>(data.data());
    const auto* end = begin + data.size();

    return std::string(begin, std::find(begin, end, '\0'));
}

std::uint32_t binary_reader_t::magic() const {
    if (data.size() < sizeof(std::uint32_t))
        throw std::out_of_range("binary_reader_t: not enough data for a magic");

    std::uint32_t value = 0;

    for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i)
        value = (value << 8) | std::to_integer<std::uint8_t>(data[i]);

    return value;
}

void binary_reader_t::set_endianness(endianness_t endianness) noexcept {
    this->endianness = endianness;
}

endianness_t binary_reader_t::get_endianness() const noexcept {
    return endianness;
}

void binary_reader_t::seek(std::size_t offset) noexcept {
    this->offset = offset;
}

void binary_reader_t::skip(std::size_t n) {
    if (!can_read(n))
        throw std::out_of_range("binary_reader_t: skip past end of data");

    offset += n;
}

std::size_t binary_reader_t::tell() const noexcept {
    return offset;
}

std::size_t binary_reader_t::remaining() const noexcept {
    return data.size() - offset;
}

bool binary_reader_t::can_read(std::size_t n) const noexcept {
    return can_read(offset, n);
}

bool binary_reader_t::can_read(std::size_t position, std::size_t n) const noexcept {
    return position <= data.size() && n <= data.size() - position;
}
