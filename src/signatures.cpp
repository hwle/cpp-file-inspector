#include "signatures.hpp"
#include <algorithm>
#include <cctype>

namespace inspector {
namespace {
bool starts_with(const std::vector<std::uint8_t>& bytes,
                 const std::vector<std::uint8_t>& prefix) {
    if (bytes.size() < prefix.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), bytes.begin());
}
} // namespace

Kind identify(const std::vector<std::uint8_t>& h) {
    if (starts_with(h, {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})) return Kind::PNG;
    if (starts_with(h, {0xff, 0xd8, 0xff})) return Kind::JPEG;
    if (starts_with(h, {'G','I','F','8','7','a'}) ||
        starts_with(h, {'G','I','F','8','9','a'})) return Kind::GIF;
    if (starts_with(h, {'%','P','D','F','-'})) return Kind::PDF;
    if (starts_with(h, {'P','K',0x03,0x04}) ||
        starts_with(h, {'P','K',0x05,0x06}) ||
        starts_with(h, {'P','K',0x07,0x08})) return Kind::ZIP;
    if (starts_with(h, {0x7f, 'E', 'L', 'F'})) return Kind::ELF;
    // MZ is only the DOS stub signature; we do not claim to validate a PE file.
    if (starts_with(h, {'M', 'Z'})) return Kind::WINDOWS_EXE_CANDIDATE;
    return Kind::UNKNOWN;
}

std::string kind_name(Kind kind) {
    switch (kind) {
        case Kind::PNG: return "PNG image";
        case Kind::JPEG: return "JPEG image";
        case Kind::GIF: return "GIF image";
        case Kind::PDF: return "PDF document";
        case Kind::ZIP: return "ZIP archive";
        case Kind::ELF: return "ELF binary";
        case Kind::WINDOWS_EXE_CANDIDATE: return "MZ executable candidate";
        default: return "Unknown signature";
    }
}

bool extension_matches(Kind kind, const std::string& extension) {
    std::string ext = extension;
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    switch (kind) {
        case Kind::PNG: return ext == ".png";
        case Kind::JPEG: return ext == ".jpg" || ext == ".jpeg";
        case Kind::GIF: return ext == ".gif";
        case Kind::PDF: return ext == ".pdf";
        case Kind::ZIP: return ext == ".zip" || ext == ".jar" || ext == ".docx" || ext == ".xlsx";
        case Kind::ELF: return ext.empty() || ext == ".elf" || ext == ".so";
        case Kind::WINDOWS_EXE_CANDIDATE: return ext == ".exe" || ext == ".dll" || ext == ".sys";
        default: return false;
    }
}
} // namespace inspector
