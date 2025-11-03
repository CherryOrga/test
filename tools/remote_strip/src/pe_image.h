#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace remote::tool {

struct stub_entry {
    std::string name;
    std::uint32_t rva{};
    std::uint32_t size{};
};

class pe_image {
public:
    pe_image() = default;

    bool load(const std::filesystem::path& path);
    bool valid() const noexcept { return m_valid; }

    std::uint64_t image_base() const noexcept { return m_image_base; }
    bool is_x64() const noexcept { return m_is_x64; }

    bool rva_to_offset(std::uint32_t rva, std::uint32_t& offset) const;
    std::optional<std::string> read_string(std::uint32_t rva) const;

    const std::vector<std::uint8_t>& data() const noexcept { return m_data; }
    std::vector<std::uint8_t>& mutable_data() noexcept { return m_data; }

    std::vector<stub_entry> discover_stub_entries() const;

private:
    struct section_header {
        std::string name;
        std::uint32_t virtual_address{};
        std::uint32_t virtual_size{};
        std::uint32_t raw_address{};
        std::uint32_t raw_size{};
    };

    const section_header* find_section_for_rva(std::uint32_t rva) const;
    const section_header* find_section_by_prefix(std::string_view prefix) const;

    std::filesystem::path m_path;
    std::vector<std::uint8_t> m_data;
    std::vector<section_header> m_sections;
    bool m_valid{false};
    bool m_is_x64{false};
    std::uint64_t m_image_base{0};
};

}  // namespace remote::tool
