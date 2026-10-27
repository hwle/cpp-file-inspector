#include "signatures.hpp"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: file-inspector <file1> [file2 ...]\n";
        return 1;
    }
    int errors = 0;
    for (int i = 1; i < argc; ++i) {
        const fs::path path(argv[i]);
        std::ifstream stream(path, std::ios::binary);
        if (!stream) {
            std::cerr << "Cannot read: " << path.string() << '\n';
            ++errors;
            continue;
        }
        std::vector<std::uint8_t> header(16, 0);
        stream.read(reinterpret_cast<char*>(header.data()),
                    static_cast<std::streamsize>(header.size()));
        header.resize(static_cast<std::size_t>(stream.gcount()));
        const auto kind = inspector::identify(header);
        std::error_code ec;
        const auto size = fs::file_size(path, ec);
        const auto ext = path.extension().string();
        const bool matches = inspector::extension_matches(kind, ext);
        std::cout << "File: " << path.string() << '\n';
        std::cout << "  Signature: " << inspector::kind_name(kind) << '\n';
        std::cout << "  Size: " << (ec ? "unknown" : std::to_string(size)) << " bytes\n";
        std::cout << "  Extension: " << (ext.empty() ? "(none)" : ext) << '\n';
        if (kind == inspector::Kind::UNKNOWN) {
            std::cout << "  Result: no supported file signature found\n";
        } else {
            std::cout << "  Result: " << (matches ? "expected extension" : "extension differs from signature") << '\n';
        }
        std::cout << '\n';
    }
    return errors ? 2 : 0;
}
