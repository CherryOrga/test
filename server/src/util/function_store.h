#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace remote {

class function_store {
 public:
  explicit function_store(std::filesystem::path root);

  void set_root(std::filesystem::path root);
  std::optional<std::vector<uint8_t>> load(const std::string& name) const;

 private:
  std::filesystem::path m_root;
};

std::string sanitize_name(const std::string& name);

}  // namespace remote

