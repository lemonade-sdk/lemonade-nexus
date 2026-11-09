#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::gossip {

/// A device is online while its latest presence time is less than this many
/// seconds old. Current SDKs send a heartbeat every 3 s, and Tier 1 servers
/// share the presence they hear every kPresenceSyncIntervalSec (3 s). Ten
/// seconds lets one heartbeat or one PresenceSync datagram go missing, plus
/// transit, without an online device reading offline on any Tier 1 server,
/// and still shows a device that stopped as offline within about 10 s.
inline constexpr uint64_t kDevicePresenceOnlineSec = 10;

/// Largest amount, in seconds, by which a gossiped presence time may be ahead
/// of this server's clock. A time within it counts as "now"; a time beyond it
/// is ignored, so a sender with a fast clock cannot hold a device online.
inline constexpr uint64_t kDevicePresenceMaxSkewSec = 5;

/// How long the table keeps a presence time after it was heard, in seconds,
/// so a peer list can report when an offline device was last present.
inline constexpr uint64_t kDevicePresenceRetentionSec = 24 * 60 * 60;

/// Most devices the table holds. Local presence needs a session that owns the
/// node, and gossiped presence comes only from Tier 1 members, so the cap
/// only bounds memory against a faulty sender.
inline constexpr std::size_t kDevicePresenceMaxEntries = 65536;

/// Longest node id the table and PresenceSync accept, in bytes.
inline constexpr std::size_t kDevicePresenceMaxNodeIdBytes = 128;

/// Interval, in seconds, at which a Tier 1 server sends the presence it heard
/// locally within kDevicePresenceOnlineSec to the other Tier 1 servers. It
/// matches the 3 s heartbeat of current SDKs.
inline constexpr uint64_t kPresenceSyncIntervalSec = 3;

/// Most entries, and most payload bytes, in one PresenceSync message. A
/// larger set goes out as several messages. A receiver refuses a message
/// beyond either bound before it parses the entries.
inline constexpr std::size_t kPresenceSyncMaxEntries      = 256;
inline constexpr std::size_t kPresenceSyncMaxPayloadBytes = 16 * 1024;

/// Most LAN endpoints a device's presence carries: the private IPv4
/// addresses of the device with its dataplane port, from its mesh heartbeat
/// (`local_endpoints`).
inline constexpr std::size_t kDevicePresenceMaxLanEndpoints = 4;

/// How long a device's LAN endpoints stay listed after the presence that
/// carried them, in seconds. Every heartbeat of a current client reports
/// them again, so they disappear from the peer lists of every Tier 1 server
/// this long after the device stops sending heartbeats.
inline constexpr uint64_t kDevicePresenceLanTtlSec = 120;

/// One presence entry: the device node `node_id` was present at `seen` (Unix
/// seconds), and reported the LAN endpoints `lan` (empty when none within
/// kDevicePresenceLanTtlSec of `seen`).
struct PresenceEntry {
    std::string              node_id;
    uint64_t                 seen{0};
    std::vector<std::string> lan;

    bool operator==(const PresenceEntry&) const = default;
};

/// True when `node_id` has 1 to kDevicePresenceMaxNodeIdBytes characters,
/// each an ASCII letter, a digit, '_' or '-' (the node ids that the mesh
/// routes accept). Pure.
[[nodiscard]] bool presence_node_id_valid(std::string_view node_id);

/// True when `text` is a LAN endpoint "a.b.c.d:port": decimal octets without
/// leading zeros, a port from 1 to 65535, and a private address (10.0.0.0/8,
/// 172.16.0.0/12, 192.168.0.0/16, or 100.64.0.0/10). A loopback address
/// (127.0.0.0/8) passes only with `allow_loopback` (a single-host deployment
/// whose server address is loopback). PresenceSync carries private addresses
/// only. Pure.
[[nodiscard]] bool presence_lan_endpoint_valid(std::string_view text, bool allow_loopback);

/// Encode `entries` as PresenceSync payloads: msgpack maps
/// {"entries": [{"node_id": "...", "seen": N, "lan"?: ["a.b.c.d:port", ...]},
/// ...]}, each within kPresenceSyncMaxEntries and
/// kPresenceSyncMaxPayloadBytes. Entries whose node id fails
/// presence_node_id_valid or whose time is 0 are left out. `lan` is present
/// only when the entry has LAN endpoints; an endpoint that fails
/// presence_lan_endpoint_valid without loopback is left out, and at most
/// kDevicePresenceMaxLanEndpoints are sent. Returns no payload when no entry
/// is left. Pure.
[[nodiscard]] std::vector<std::vector<uint8_t>> encode_presence_sync(
    const std::vector<PresenceEntry>& entries);

/// Decode one PresenceSync payload. Returns nullopt when the payload is
/// empty, larger than kPresenceSyncMaxPayloadBytes, not msgpack, not the
/// map above, has no entries or more than kPresenceSyncMaxEntries, or has an
/// entry whose node id fails presence_node_id_valid, whose `seen` is not a
/// positive integer, or whose `lan` is present and is not an array of at
/// most kDevicePresenceMaxLanEndpoints distinct strings that pass
/// presence_lan_endpoint_valid without loopback. An entry without `lan` (a
/// sender from before the field) decodes with no LAN endpoints. Unknown keys
/// are ignored. Checks no clock. Pure.
[[nodiscard]] std::optional<std::vector<PresenceEntry>> decode_presence_sync(
    std::span<const uint8_t> payload);

/// Device presence: the latest time each device node was present at this
/// server (an authenticated heartbeat or an open event socket of the device)
/// or at another Tier 1 server (PresenceSync), and the LAN endpoints the
/// device reported with it.
///
/// Presence is a liveness hint for display and path decisions. It grants
/// nothing: no authorization decision may read it. LAN endpoints are
/// advisory send targets for the peers that already list the device; the
/// BoringTun handshake still authenticates the peer by its mesh key.
///
/// Times are Unix seconds that the caller passes in. The table keeps the
/// largest time it saw for each device, so a merge never moves a time back.
/// The LAN endpoints follow the presence time: the entry that raises a
/// device's time also sets its LAN endpoints, so every Tier 1 server lists
/// what the server that last heard the device lists.
///
/// Thread-safe.
class DevicePresence {
public:
    DevicePresence() = default;
    DevicePresence(const DevicePresence&)            = delete;
    DevicePresence& operator=(const DevicePresence&) = delete;

    /// What a device reads at one moment.
    struct Status {
        bool     online{false};  ///< present within kDevicePresenceOnlineSec
        uint64_t last_seen{0};   ///< latest presence time, 0 when none is held
    };

    /// The outcome of record_local.
    struct LocalResult {
        bool accepted{false};       ///< false for an invalid node id or a full table
        bool became_online{false};  ///< the device was not online before
        bool locally_new{false};    ///< this server had not heard it within the window
        bool lan_changed{false};    ///< the listed LAN endpoints differ from before
    };

    /// The outcome of merge_remote.
    struct MergeResult {
        std::size_t merged{0};      ///< entries that raised a stored time or added one
        std::size_t ahead{0};       ///< entries ignored: beyond kDevicePresenceMaxSkewSec
        bool        became_online{false};
        bool        lan_changed{false};  ///< a device's listed LAN endpoints changed
    };

    /// The outcome of sweep.
    struct Sweep {
        bool     went_offline{false};  ///< a device went offline since the last sweep
        uint64_t next_expiry{0};       ///< earliest time an online device goes offline; 0 if none
    };

    /// Record that `node_id` was present at this server at `now`, with the
    /// LAN endpoints it reported: nullopt leaves the stored list as it is (a
    /// heartbeat without the field, or an event socket), an empty list
    /// removes it, and any other list replaces it and restarts its
    /// kDevicePresenceLanTtlSec. The caller must have authenticated the
    /// device as the owner of the node and validated each endpoint
    /// (presence_lan_endpoint_valid) and the count
    /// (kDevicePresenceMaxLanEndpoints). Calls the changed hook when the
    /// device becomes online or its listed LAN endpoints change.
    LocalResult record_local(const std::string& node_id, uint64_t now,
                             std::optional<std::vector<std::string>> lan = std::nullopt);

    /// Merge presence from another Tier 1 server, by maximum time. A time
    /// more than kDevicePresenceMaxSkewSec after `now` is ignored, a later
    /// time within it counts as `now`, and a time older than
    /// kDevicePresenceRetentionSec is ignored. Invalid node ids are ignored.
    /// An entry that raises a device's time also replaces its LAN endpoints
    /// with the entry's (none when the entry has none), dated at that time.
    /// Entries must come from decode_presence_sync, which validates each
    /// endpoint. Calls the changed hook once when any device becomes online
    /// or any listed LAN endpoints change.
    MergeResult merge_remote(const std::vector<PresenceEntry>& entries, uint64_t now);

    /// Presence of `node_id` at `now`.
    [[nodiscard]] Status status(const std::string& node_id, uint64_t now) const;

    /// The LAN endpoints `node_id` reported, here or at another Tier 1
    /// server, within kDevicePresenceLanTtlSec of `now`; empty when none.
    [[nodiscard]] std::vector<std::string> lan_endpoints(const std::string& node_id,
                                                         uint64_t now) const;

    /// The devices this server heard itself within kDevicePresenceOnlineSec
    /// of `now`, with the latest local time of each and the LAN endpoints
    /// listed at `now`, sorted by node id. A time learned from another server
    /// is never in this list, so presence is never relayed.
    [[nodiscard]] std::vector<PresenceEntry> local_online(uint64_t now) const;

    /// Note the devices that went offline since the last sweep, drop entries
    /// older than kDevicePresenceRetentionSec and LAN endpoints older than
    /// kDevicePresenceLanTtlSec, and report the next expiry. Does not call the
    /// changed hook; the caller wakes its own waiters.
    Sweep sweep(uint64_t now);

    /// Set the function called when a device becomes online or its listed LAN
    /// endpoints change (record_local or merge_remote). It runs on the
    /// recording thread, after the table lock is released, and must not call
    /// back into this table. Replacing the hook waits until a running call
    /// returns, so the old hook's owner may be destroyed after this returns.
    void set_changed_hook(std::function<void()> hook);

    /// Devices held now.
    [[nodiscard]] std::size_t size() const;

private:
    struct Entry {
        uint64_t                 seen{0};        ///< latest time from any source
        uint64_t                 local_seen{0};  ///< latest time heard at this server
        bool                     online{false};  ///< online state as of the last update or sweep
        std::vector<std::string> lan;            ///< LAN endpoints reported with the presence
        uint64_t                 lan_at{0};      ///< time `lan` was reported; 0 when none
    };

    /// The entry for `node_id`, created when absent and the table has room.
    /// Requires mtx_.
    Entry* find_or_add_locked(const std::string& node_id, uint64_t now);
    void   notify_changed();

    mutable std::mutex                     mtx_;
    std::unordered_map<std::string, Entry> entries_;
    std::mutex                             hook_mtx_;
    std::function<void()>                  hook_;
};

}  // namespace nexus::gossip
