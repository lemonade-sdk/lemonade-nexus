#pragma once

// Release versioning (design: Versioning).
//
//   tag             vYYYY.MM.DD for the first release of a day, then
//                   vYYYY.MM.DD.2, vYYYY.MM.DD.3, ... up to .99
//   release number  YYYYMMDD * 100 + N, where N is 1 for the first release
//
// The number is derived from the tag and nothing else. The signed release
// approval carries the tag as its release_id, so the number is covered by the
// release signature without a change to the approval format.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::updater {

struct ReleaseTag {
    std::string tag;
    int year{0};
    int month{0};
    int day{0};
    /// 1 for vYYYY.MM.DD, otherwise the suffix (2..99).
    int sequence{1};
    uint64_t number{0};
};

/// Parse a canonical tag. nullopt for anything else: a missing "v", a date
/// that does not exist, a ".1" or zero-padded suffix, or a suffix over 99.
[[nodiscard]] std::optional<ReleaseTag> parse_release_tag(std::string_view tag);

/// The canonical tag for a date and sequence. Empty when invalid.
[[nodiscard]] std::string format_release_tag(int year, int month, int day, int sequence);

}  // namespace nexus::updater
