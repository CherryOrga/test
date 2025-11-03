#include "function_store.h"

#include <cctype>
#include <fstream>
#include <iterator>

namespace remote {

function_store::function_store(std::filesystem::path root) : m_root(std::move(root)) {}

void function_store::set_root(std::filesystem::path root) { m_root = std::move(root); }

std::optional<std::vector<uint8_t>> function_store::load(const std::string& name) const {
  auto sanitized = sanitize_name(name);
  if (sanitized.empty()) {
    return std::nullopt;
  }

  auto path = m_root / (sanitized + ".bytes");
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }

  std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  return buffer;
}

std::string sanitize_name(const std::string& name) {
  std::string sanitized;
  sanitized.reserve(name.size());
  for (char ch : name) {
    unsigned char c = static_cast<unsigned char>(ch);
    if (std::isalnum(c) || c == '_' || c == '-') {
      sanitized.push_back(static_cast<char>(c));
    } else if (ch == ':' || ch == '.') {
      sanitized.push_back('_');
    }
  }
  return sanitized;
}

}  // namespace remote

