#include "signatures.hpp"
#include <cassert>
#include <cstdint>
#include <vector>

using inspector::Kind;
int main() {
    assert(inspector::identify({0x89, 'P','N','G',13,10,26,10}) == Kind::PNG);
    assert(inspector::identify({0xff,0xd8,0xff,0xe0}) == Kind::JPEG);
    assert(inspector::identify({'%','P','D','F','-','1','.','7'}) == Kind::PDF);
    assert(inspector::identify({'P','K',3,4}) == Kind::ZIP);
    assert(inspector::identify({0x7f, 'E','L','F'}) == Kind::ELF);
    assert(inspector::identify({'M','Z'}) == Kind::WINDOWS_EXE_CANDIDATE);
    assert(inspector::identify({}) == Kind::UNKNOWN);
    assert(inspector::extension_matches(Kind::JPEG, ".JPG"));
    assert(inspector::extension_matches(Kind::ZIP, ".docx"));
    assert(!inspector::extension_matches(Kind::PNG, ".txt"));
    return 0;
}
