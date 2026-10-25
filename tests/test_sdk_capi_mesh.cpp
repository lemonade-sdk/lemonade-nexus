// C ABI contract for the mesh and node-role calls an embedding application
// (the Lemonade server) uses: argument checks and inactive-mesh behavior.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <gtest/gtest.h>

#include <string>

namespace {

struct Client {
    ln_client_t* c = ln_create("localhost", 9);
    ~Client() { if (c) ln_destroy(c); }
};

}  // namespace

TEST(SdkCapiMesh, NullArgumentsAreRefused) {
    EXPECT_EQ(ln_set_inference_node(nullptr, 1), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_close_egress(nullptr, "10.64.0.2", 13305), LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_mesh_close_egress(client.c, nullptr, 13305), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_is_active(nullptr), 0);
}

TEST(SdkCapiMesh, InferenceRoleAndInactiveMeshCalls) {
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_set_inference_node(client.c, 1), LN_OK);
    EXPECT_EQ(ln_set_inference_node(client.c, 0), LN_OK);
    // Before a join the dataplane is down: nothing is active, closing an
    // egress that was never opened is a harmless no-op, and opening fails.
    EXPECT_EQ(ln_mesh_is_active(client.c), 0);
    EXPECT_EQ(ln_mesh_close_egress(client.c, "10.64.0.2", 13305), LN_OK);
    uint16_t port = 1;
    EXPECT_EQ(ln_mesh_open_egress(client.c, "10.64.0.2", 13305, &port), LN_ERR_CONNECT);
}

// Invite, membership, and move calls: argument checks, the caller-owned
// out_json, and the inactive-mesh result (these are private-API calls).
TEST(SdkCapiMesh, InviteMembershipAndMoveCallsCheckArguments) {
    char* out = nullptr;
    EXPECT_EQ(ln_invite_create(nullptr, nullptr, nullptr, 600, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_invite_accept(nullptr, "lnk_x", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_memberships_list(nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_membership_leave(nullptr, "g", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_move_node(nullptr, "n", "g", &out), LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_invite_create(client.c, nullptr, nullptr, 600, nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_invite_accept(client.c, nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_membership_leave(client.c, nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_move_node(client.c, "n", nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_move_node(client.c, nullptr, "g", &out), LN_ERR_NULL_ARG);
    // A permissions argument that is not a JSON array of strings is refused
    // before any request.
    EXPECT_EQ(ln_invite_create(client.c, "g", "{\"read\":1}", 600, &out), LN_ERR_REJECTED);
    EXPECT_EQ(ln_invite_create(client.c, "g", "[\"read\", 3]", 600, &out), LN_ERR_REJECTED);
    EXPECT_EQ(out, nullptr);
}

TEST(SdkCapiMesh, InviteCallsWithoutAMeshFailAndReturnAnError) {
    Client client;
    ASSERT_NE(client.c, nullptr);
    char* out = nullptr;
    EXPECT_EQ(ln_invite_create(client.c, nullptr, "[\"read\"]", 600, &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    EXPECT_NE(std::string(out).find("error"), std::string::npos);
    ln_free(out);
    out = nullptr;
    EXPECT_EQ(ln_invite_accept(client.c, "lnk_x", &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    ln_free(out);
    out = nullptr;
    EXPECT_EQ(ln_memberships_list(client.c, &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    ln_free(out);
    out = nullptr;
    EXPECT_EQ(ln_move_node(client.c, "n", "g", &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    ln_free(out);
}
