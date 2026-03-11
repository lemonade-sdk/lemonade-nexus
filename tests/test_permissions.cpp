#include <LemonadeNexus/ACL/Permission.hpp>

#include <gtest/gtest.h>

using namespace nexus::acl;

TEST(PermissionTest, NoneHasNoPermissions) {
    EXPECT_FALSE(has_permission(Permission::None, Permission::Read));
    EXPECT_FALSE(has_permission(Permission::None, Permission::Write));
    EXPECT_FALSE(has_permission(Permission::None, Permission::Admin));
}

TEST(PermissionTest, SinglePermissionCheck) {
    EXPECT_TRUE(has_permission(Permission::Read, Permission::Read));
    EXPECT_FALSE(has_permission(Permission::Read, Permission::Write));
}

TEST(PermissionTest, CombinedPermissions) {
    auto perms = Permission::Read | Permission::Write | Permission::AddChild;
    EXPECT_TRUE(has_permission(perms, Permission::Read));
    EXPECT_TRUE(has_permission(perms, Permission::Write));
    EXPECT_TRUE(has_permission(perms, Permission::AddChild));
    EXPECT_FALSE(has_permission(perms, Permission::DeleteNode));
    EXPECT_FALSE(has_permission(perms, Permission::Admin));
}

TEST(PermissionTest, AdminHasAllPermissions) {
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::Read));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::Write));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::AddChild));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::EditNode));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::DeleteNode));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::ExpandSubnet));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::ConnectPrivate));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::ConnectShared));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::RelayForward));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::StunRespond));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::RelayRegister));
    EXPECT_TRUE(has_permission(Permission::Admin, Permission::AllocateIP));
}

TEST(PermissionTest, BitwiseOrCombines) {
    auto p = Permission::Read | Permission::Write;
    EXPECT_EQ(static_cast<uint32_t>(p), 0x03u);
}

TEST(PermissionTest, BitwiseAndMasks) {
    auto combined = Permission::Read | Permission::Write | Permission::AddChild;
    auto masked = combined & Permission::Write;
    EXPECT_EQ(masked, Permission::Write);
}

TEST(PermissionTest, NoneHasZeroValue) {
    EXPECT_EQ(static_cast<uint32_t>(Permission::None), 0u);
}

TEST(PermissionTest, PermissionsArePowerOfTwo) {
    EXPECT_EQ(static_cast<uint32_t>(Permission::Read), 1u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::Write), 2u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::AddChild), 4u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::EditNode), 8u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::DeleteNode), 16u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::ExpandSubnet), 32u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::ConnectPrivate), 64u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::ConnectShared), 128u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::RelayForward), 256u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::StunRespond), 512u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::RelayRegister), 1024u);
    EXPECT_EQ(static_cast<uint32_t>(Permission::AllocateIP), 2048u);
}
