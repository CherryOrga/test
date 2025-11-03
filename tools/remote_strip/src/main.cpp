#include "pe_image.h"
#include "pdb_symbols.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <json.hpp>

namespace remote::tool {
namespace {

struct options {
    std::filesystem::path input_image;
    std::filesystem::path output_directory;
    std::optional<std::filesystem::path> pdb_file;
    std::optional<std::filesystem::path> stripped_output;
    std::optional<std::filesystem::path> manifest_path;
};

void print_usage() {
    std::cerr << "Usage: remote_strip --input <image> --output <dir> [--pdb <file>] [--stripped <file>] [--manifest <file>]" << std::endl;
}

bool parse_arguments(int argc, char** argv, options& out) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto require_value = [&](const std::string& name) -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for argument " << name << std::endl;
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };

        if (arg == "--input") {
            if (auto value = require_value(arg)) {
                out.input_image = *value;
            } else {
                return false;
            }
        } else if (arg == "--output") {
            if (auto value = require_value(arg)) {
                out.output_directory = *value;
            } else {
                return false;
            }
        } else if (arg == "--pdb") {
            if (auto value = require_value(arg)) {
                out.pdb_file = *value;
            } else {
                return false;
            }
        } else if (arg == "--stripped") {
            if (auto value = require_value(arg)) {
                out.stripped_output = *value;
            } else {
                return false;
            }
        } else if (arg == "--manifest") {
            if (auto value = require_value(arg)) {
                out.manifest_path = *value;
            } else {
                return false;
            }
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return false;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return false;
        }
    }

    if (out.input_image.empty() || out.output_directory.empty()) {
        std::cerr << "Both --input and --output arguments are required." << std::endl;
        return false;
    }

    return true;
}

std::string sanitize_name(const std::string& name) {
    std::string sanitized;
    sanitized.reserve(name.size());

    for (char ch : name) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (std::isalnum(c) || ch == '_' || ch == '-') {
            sanitized.push_back(static_cast<char>(c));
        } else if (ch == ':' || ch == '.') {
            sanitized.push_back('_');
        }
    }

    return sanitized;
}

std::filesystem::path default_stripped_path(const std::filesystem::path& input) {
    auto directory = input.parent_path();
    auto stem = input.stem().string();
    auto extension = input.extension().string();
    std::filesystem::path candidate = directory / (stem + ".stripped" + extension);
    return candidate;
}

}  // namespace
}  // namespace remote::tool

#ifdef _WIN32
int main(int argc, char** argv) {
    using namespace remote::tool;

    options opts;
    if (!parse_arguments(argc, argv, opts)) {
        return 1;
    }

    pe_image image;
    if (!image.load(opts.input_image)) {
        std::cerr << "Failed to load input image: " << opts.input_image << std::endl;
        return 1;
    }

    auto stubs = image.discover_stub_entries();
    if (stubs.empty()) {
        std::cerr << "No remote function stubs discovered in image." << std::endl;
        return 1;
    }

    pdb_symbols pdb;
    bool has_pdb = false;
    if (opts.pdb_file) {
        has_pdb = pdb.load(*opts.pdb_file, image.image_base());
        if (!has_pdb) {
            std::cerr << "Warning: failed to open PDB file: " << *opts.pdb_file << std::endl;
        }
    }

    if (has_pdb) {
        for (auto& stub : stubs) {
            if (auto length = pdb.function_size(stub.rva)) {
                if (*length > 0) {
                    stub.size = *length;
                }
            }
        }
    }

    for (std::size_t i = 0; i < stubs.size(); ++i) {
        if (stubs[i].size == 0) {
            std::cerr << "Warning: unable to determine size for remote function " << stubs[i].name
                      << ", it will be skipped." << std::endl;
        }
    }

    std::filesystem::create_directories(opts.output_directory);

    std::unordered_map<std::string, std::size_t> occurrences;
    nlohmann::json manifest;
    manifest["image"] = opts.input_image.string();
    manifest["image_base"] = image.image_base();
    manifest["functions"] = nlohmann::json::array();

    auto& bytes_ref = image.mutable_data();

    for (const auto& stub : stubs) {
        if (stub.size == 0) {
            continue;
        }

        std::uint32_t offset = 0;
        if (!image.rva_to_offset(stub.rva, offset)) {
            std::cerr << "Warning: unable to translate RVA for function " << stub.name << std::endl;
            continue;
        }

        if (static_cast<std::size_t>(offset) + stub.size > bytes_ref.size()) {
            std::cerr << "Warning: function " << stub.name << " extends beyond image bounds." << std::endl;
            continue;
        }

        auto sanitized = sanitize_name(stub.name);
        if (sanitized.empty()) {
            sanitized = "remote_stub";
        }

        auto index = occurrences[sanitized]++;
        if (index > 0) {
            sanitized += "_" + std::to_string(index);
        }

        auto output_path = opts.output_directory / (sanitized + ".bytes");
        std::vector<std::uint8_t> buffer(bytes_ref.begin() + offset, bytes_ref.begin() + offset + stub.size);

        std::ofstream out(output_path, std::ios::binary);
        if (!out) {
            std::cerr << "Warning: failed to write bytes for function " << stub.name << std::endl;
            continue;
        }

        out.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        out.close();

        std::fill(bytes_ref.begin() + offset, bytes_ref.begin() + offset + stub.size, 0x90);

        nlohmann::json entry;
        entry["name"] = stub.name;
        entry["file"] = output_path.filename().string();
        entry["rva"] = stub.rva;
        entry["size"] = stub.size;
        manifest["functions"].push_back(entry);

        std::cout << "Stripped remote function " << stub.name << " (" << stub.size << " bytes)." << std::endl;
    }

    auto manifest_path = opts.manifest_path.value_or(opts.output_directory / "remote_functions.json");
    std::ofstream manifest_stream(manifest_path);
    if (!manifest_stream) {
        std::cerr << "Warning: failed to write manifest file at " << manifest_path << std::endl;
    } else {
        manifest_stream << manifest.dump(2);
    }

    auto stripped_path = opts.stripped_output.value_or(default_stripped_path(opts.input_image));
    std::ofstream stripped_stream(stripped_path, std::ios::binary);
    if (!stripped_stream) {
        std::cerr << "Warning: failed to write stripped image at " << stripped_path << std::endl;
    } else {
        stripped_stream.write(reinterpret_cast<const char*>(bytes_ref.data()),
                              static_cast<std::streamsize>(bytes_ref.size()));
    }

    return 0;
}
#else
int main() {
    std::cerr << "remote_strip can only be executed on Windows." << std::endl;
    return 1;
}
#endif
