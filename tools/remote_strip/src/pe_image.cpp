#include "pe_image.h"

#ifdef _WIN32
#include <Windows.h>
#endif

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

namespace remote::tool {

namespace {
constexpr std::string_view kStubSectionPrefix{".remstub"};
}

bool pe_image::load(const std::filesystem::path& path) {
    m_path = path;
    m_valid = false;
    m_sections.clear();
    m_data.clear();

#ifndef _WIN32
    (void)path;
    return false;
#else
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    m_data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    if (m_data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > m_data.size()) {
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    m_is_x64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    if (m_is_x64) {
        const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt);
        m_image_base = nt64->OptionalHeader.ImageBase;
        auto* section = IMAGE_FIRST_SECTION(nt64);
        for (unsigned i = 0; i < nt64->FileHeader.NumberOfSections; ++i, ++section) {
            section_header info{};
            info.name = std::string(reinterpret_cast<const char*>(section->Name),
                                    strnlen(reinterpret_cast<const char*>(section->Name), IMAGE_SIZEOF_SHORT_NAME));
            info.virtual_address = section->VirtualAddress;
            info.virtual_size = section->Misc.VirtualSize;
            info.raw_address = section->PointerToRawData;
            info.raw_size = section->SizeOfRawData;
            m_sections.emplace_back(std::move(info));
        }
    } else {
        const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt);
        m_image_base = nt32->OptionalHeader.ImageBase;
        auto* section = IMAGE_FIRST_SECTION(nt32);
        for (unsigned i = 0; i < nt32->FileHeader.NumberOfSections; ++i, ++section) {
            section_header info{};
            info.name = std::string(reinterpret_cast<const char*>(section->Name),
                                    strnlen(reinterpret_cast<const char*>(section->Name), IMAGE_SIZEOF_SHORT_NAME));
            info.virtual_address = section->VirtualAddress;
            info.virtual_size = section->Misc.VirtualSize;
            info.raw_address = section->PointerToRawData;
            info.raw_size = section->SizeOfRawData;
            m_sections.emplace_back(std::move(info));
        }
    }

    m_valid = true;
    return true;
#endif
}

bool pe_image::rva_to_offset(std::uint32_t rva, std::uint32_t& offset) const {
#ifndef _WIN32
    (void)rva;
    (void)offset;
    return false;
#else
    const auto* section = find_section_for_rva(rva);
    if (!section) {
        return false;
    }

    auto relative = rva - section->virtual_address;
    if (relative >= section->raw_size) {
        return false;
    }

    offset = section->raw_address + relative;
    return offset < m_data.size();
#endif
}

std::optional<std::string> pe_image::read_string(std::uint32_t rva) const {
    std::uint32_t offset = 0;
    if (!rva_to_offset(rva, offset)) {
        return std::nullopt;
    }

    if (offset >= m_data.size()) {
        return std::nullopt;
    }

    const auto* begin = reinterpret_cast<const char*>(m_data.data() + offset);
    const auto* end = reinterpret_cast<const char*>(m_data.data() + m_data.size());
    auto it = std::find(begin, end, '\0');
    if (it == end) {
        return std::nullopt;
    }

    return std::string(begin, it);
}

const pe_image::section_header* pe_image::find_section_for_rva(std::uint32_t rva) const {
    for (const auto& section : m_sections) {
        auto limit = section.virtual_size ? section.virtual_size : section.raw_size;
        if (rva >= section.virtual_address && rva < section.virtual_address + limit) {
            return &section;
        }
    }

    return nullptr;
}

const pe_image::section_header* pe_image::find_section_by_prefix(std::string_view prefix) const {
    for (const auto& section : m_sections) {
        if (section.name.rfind(prefix, 0) == 0) {
            return &section;
        }
    }

    return nullptr;
}

std::vector<stub_entry> pe_image::discover_stub_entries() const {
    std::vector<stub_entry> entries;

#ifndef _WIN32
    return entries;
#else
    if (!m_valid) {
        return entries;
    }

    const auto* stub_section = find_section_by_prefix(kStubSectionPrefix);
    if (!stub_section) {
        return entries;
    }

    const auto pointer_size = m_is_x64 ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
    if (stub_section->raw_address + stub_section->raw_size > m_data.size()) {
        return entries;
    }

    const auto* base = m_data.data() + stub_section->raw_address;
    const auto count = stub_section->raw_size / pointer_size;

    for (std::size_t i = 0; i < count; ++i) {
        std::uint64_t descriptor_va = 0;
        if (m_is_x64) {
            descriptor_va = *(reinterpret_cast<const std::uint64_t*>(base) + i);
        } else {
            descriptor_va = *(reinterpret_cast<const std::uint32_t*>(base) + i);
        }

        if (descriptor_va == 0) {
            continue;
        }

        if (descriptor_va < m_image_base) {
            continue;
        }

        const auto descriptor_rva = static_cast<std::uint32_t>(descriptor_va - m_image_base);
        std::uint32_t descriptor_offset = 0;
        if (!rva_to_offset(descriptor_rva, descriptor_offset)) {
            continue;
        }

        if (descriptor_offset + pointer_size * 2 > m_data.size()) {
            continue;
        }

        std::uint64_t name_va = 0;
        std::uint64_t address_va = 0;
        if (m_is_x64) {
            const auto* ptr = reinterpret_cast<const std::uint64_t*>(m_data.data() + descriptor_offset);
            name_va = ptr[0];
            address_va = ptr[1];
        } else {
            const auto* ptr = reinterpret_cast<const std::uint32_t*>(m_data.data() + descriptor_offset);
            name_va = ptr[0];
            address_va = ptr[1];
        }

        if (name_va < m_image_base || address_va < m_image_base) {
            continue;
        }

        const auto name_rva = static_cast<std::uint32_t>(name_va - m_image_base);
        const auto address_rva = static_cast<std::uint32_t>(address_va - m_image_base);

        auto name = read_string(name_rva);
        if (!name || name->empty()) {
            continue;
        }

        stub_entry entry{};
        entry.name = *name;
        entry.rva = address_rva;
        entries.emplace_back(std::move(entry));
    }

    std::sort(entries.begin(), entries.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.rva < rhs.rva;
    });

    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto* section = find_section_for_rva(entries[i].rva);
        if (!section) {
            continue;
        }

        auto section_limit = section->virtual_size ? section->virtual_size : section->raw_size;
        auto section_end = section->virtual_address + section_limit;

        std::uint32_t next_rva = section_end;
        for (std::size_t j = i + 1; j < entries.size(); ++j) {
            if (const auto* next_section = find_section_for_rva(entries[j].rva); next_section == section) {
                next_rva = entries[j].rva;
                break;
            }
        }

        if (next_rva > entries[i].rva) {
            entries[i].size = next_rva - entries[i].rva;
        }
    }

    return entries;
#endif
}

}  // namespace remote::tool
