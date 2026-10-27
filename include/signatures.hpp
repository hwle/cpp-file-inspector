#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace inspector {
enum class Kind { PNG, JPEG, GIF, PDF, ZIP, ELF, WINDOWS_EXE_CANDIDATE, UNKNOWN };

Kind identify(const std::vector<std::uint8_t>& header);
std::string kind_name(Kind kind);
bool extension_matches(Kind kind, const std::string& extension);
} // namespace inspector
