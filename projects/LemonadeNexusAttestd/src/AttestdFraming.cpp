#include <LemonadeNexusAttestd/AttestdFraming.hpp>

namespace nexus::attestd {

std::string encode_frame(FrameKind kind, std::string_view payload) {
    if (payload.size() > kMaxLocalFrameBytes) return {};

    const auto len = static_cast<uint32_t>(payload.size());
    std::string out;
    out.reserve(kFrameHeaderBytes + payload.size());
    out.push_back(static_cast<char>((len >> 24) & 0xFF));
    out.push_back(static_cast<char>((len >> 16) & 0xFF));
    out.push_back(static_cast<char>((len >> 8) & 0xFF));
    out.push_back(static_cast<char>(len & 0xFF));
    out.push_back(static_cast<char>(kind));
    out.append(payload);
    return out;
}

std::string_view frame_error_name(FrameError e) {
    switch (e) {
        case FrameError::None:          return "None";
        case FrameError::Truncated:     return "Truncated";
        case FrameError::Oversized:     return "Oversized";
        case FrameError::TooManyChunks: return "TooManyChunks";
        case FrameError::TooLarge:      return "TooLarge";
        case FrameError::Malformed:     return "Malformed";
    }
    return "Unknown";
}

}  // namespace nexus::attestd
