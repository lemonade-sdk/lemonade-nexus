#include <LemonadeNexusUpdater/ReleaseTag.hpp>

#include <cstdio>

namespace nexus::updater {
namespace {

bool leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

int days_in_month(int y, int m) {
    static constexpr int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && leap(y) ? 29 : kDays[m - 1];
}

std::optional<int> digits(std::string_view s) {
    if (s.empty() || s.size() > 4) return std::nullopt;
    int v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

bool valid_date(int y, int m, int d) {
    return y >= 2000 && y <= 9999 && m >= 1 && m <= 12 && d >= 1 && d <= days_in_month(y, m);
}

}  // namespace

std::optional<ReleaseTag> parse_release_tag(std::string_view tag) {
    // vYYYY.MM.DD is 11 characters; the longest form adds ".NN".
    if (tag.size() != 11 && tag.size() != 13 && tag.size() != 14) return std::nullopt;
    if (tag[0] != 'v' || tag[5] != '.' || tag[8] != '.') return std::nullopt;
    const auto y = digits(tag.substr(1, 4));
    const auto m = digits(tag.substr(6, 2));
    const auto d = digits(tag.substr(9, 2));
    if (!y || !m || !d || !valid_date(*y, *m, *d)) return std::nullopt;
    int sequence = 1;
    if (tag.size() > 11) {
        if (tag[11] != '.') return std::nullopt;
        const auto suffix = tag.substr(12);
        const auto n = digits(suffix);
        if (!n || suffix[0] == '0' || *n < 2 || *n > 99) return std::nullopt;
        sequence = *n;
    }
    ReleaseTag out;
    out.tag = std::string(tag);
    out.year = *y;
    out.month = *m;
    out.day = *d;
    out.sequence = sequence;
    out.number = (static_cast<uint64_t>(*y) * 10000 + static_cast<uint64_t>(*m) * 100 +
                  static_cast<uint64_t>(*d)) * 100 + static_cast<uint64_t>(sequence);
    return out;
}

std::string format_release_tag(int year, int month, int day, int sequence) {
    if (!valid_date(year, month, day) || sequence < 1 || sequence > 99) return {};
    char buf[32];
    if (sequence == 1) {
        std::snprintf(buf, sizeof(buf), "v%04d.%02d.%02d", year, month, day);
    } else {
        std::snprintf(buf, sizeof(buf), "v%04d.%02d.%02d.%d", year, month, day, sequence);
    }
    return buf;
}

}  // namespace nexus::updater
