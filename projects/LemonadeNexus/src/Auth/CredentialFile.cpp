#include <LemonadeNexus/Auth/CredentialFile.hpp>

#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <system_error>

namespace nexus::auth {

namespace fs = std::filesystem;
using json = nlohmann::json;

fs::path credential_directory(const storage::FileStorageService& storage) {
    return storage.data_root() / "credentials";
}

fs::path credential_path(const storage::FileStorageService& storage, const std::string& user_id) {
    return credential_directory(storage) / (user_id + ".json");
}

fs::path revocation_path(const storage::FileStorageService& storage) {
    return credential_directory(storage) / "revoked.json";
}

CredentialFile read_credential_file(const storage::FileStorageService& storage,
                                    const fs::path& path) {
    CredentialFile out;
    std::string text;
    if (auto* vault = storage.vault_for(path)) {
        auto read = vault->read(path);
        switch (read.status) {
            case security::VaultReadStatus::Missing:
                return out;
            case security::VaultReadStatus::Ok:
                text = std::move(read.bytes);
                break;
            case security::VaultReadStatus::Locked:
            case security::VaultReadStatus::Rejected:
                spdlog::error("[credentials] {} does not open under the data key ({})",
                              path.filename().string(),
                              read.status == security::VaultReadStatus::Locked ? "locked"
                                                                               : "refused");
                out.state = CredentialFileState::Unreadable;
                return out;
        }
    } else {
        std::error_code ec;
        const auto status = fs::status(path, ec);
        if (ec || !fs::exists(status)) {
            // A failure other than "not there" leaves absence unconfirmed.
            if (!ec || ec == std::errc::no_such_file_or_directory) return out;
            out.state = CredentialFileState::Unreadable;
            return out;
        }
        std::ifstream in(path, std::ios::binary);
        std::ostringstream buffer;
        if (in) buffer << in.rdbuf();
        if (!in || in.bad()) {
            out.state = CredentialFileState::Unreadable;
            return out;
        }
        text = std::move(buffer).str();
    }
    auto parsed = json::parse(text, nullptr, false);
    if (parsed.is_discarded()) {
        spdlog::error("[credentials] {} is not valid JSON", path.filename().string());
        out.state = CredentialFileState::Unreadable;
        return out;
    }
    out.state = CredentialFileState::Present;
    out.data = std::move(parsed);
    return out;
}

bool write_credential_file(const storage::FileStorageService& storage, const fs::path& path,
                           const json& data) {
    const auto text = data.dump(2);
    if (auto* vault = storage.vault_for(path)) return vault->write(path, text);
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    return security::write_durable(path, text);
}

CredentialListing list_credential_files(const storage::FileStorageService& storage) {
    CredentialListing listing;
    const auto dir = credential_directory(storage);
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        listing.complete = !ec;
        return listing;
    }
    auto it = fs::directory_iterator(dir, ec);
    for (; !ec && it != fs::directory_iterator(); it.increment(ec)) {
        const auto& path = it->path();
        if (path.extension() != ".json") continue;  // *.json.tmp, *.json.vault-new
        listing.files.push_back(path);
    }
    if (ec) {
        spdlog::error("[credentials] scan of {} failed: {}", dir.string(), ec.message());
        listing.complete = false;
    }
    std::sort(listing.files.begin(), listing.files.end());
    return listing;
}

}  // namespace nexus::auth
