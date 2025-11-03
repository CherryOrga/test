#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>

namespace remote::tool {

class pdb_symbols {
public:
    pdb_symbols();
    ~pdb_symbols();

    bool load(const std::filesystem::path& pdb_path, std::uint64_t image_base);
    std::optional<std::uint32_t> function_size(std::uint32_t rva) const;

private:
#ifdef _WIN32
    struct com_init;
    com_init* m_com{};
    struct impl;
    impl* m_impl{};
#endif
};

}  // namespace remote::tool
