#pragma once

#include <LemonadeNexus/ACL/Permission.hpp>

#include <string>
#include <string_view>

namespace nexus::acl {

/// CRTP base for ACL providers.
/// Derived must implement:
///   Permission do_get_permissions(std::string_view user_id, std::string_view resource) const
///   bool do_grant(std::string_view user_id, std::string_view resource, Permission perms)
///   bool do_revoke(std::string_view user_id, std::string_view resource, Permission perms)
template <typename Derived>
class IACLProvider {
public:
    [[nodiscard]] Permission get_permissions(std::string_view user_id, std::string_view resource) const {
        return self().do_get_permissions(user_id, resource);
    }

    bool grant(std::string_view user_id, std::string_view resource, Permission perms) {
        return self().do_grant(user_id, resource, perms);
    }

    bool revoke(std::string_view user_id, std::string_view resource, Permission perms) {
        return self().do_revoke(user_id, resource, perms);
    }

    [[nodiscard]] bool check(std::string_view user_id, std::string_view resource, Permission required) const {
        return has_permission(get_permissions(user_id, resource), required);
    }

protected:
    ~IACLProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

} // namespace nexus::acl
