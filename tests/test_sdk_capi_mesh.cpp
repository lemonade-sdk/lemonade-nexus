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

// The device name for the next join: argument checks and the names refused
// before any request.
TEST(SdkCapiMesh, DeviceNameIsCheckedBeforeTheJoin) {
    EXPECT_EQ(ln_set_device_name(nullptr, "Work PC"), LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_set_device_name(client.c, "Work PC"), LN_OK);
    EXPECT_EQ(ln_set_device_name(client.c, nullptr), LN_OK) << "NULL clears the name";
    EXPECT_EQ(ln_set_device_name(client.c, ""), LN_OK);
    for (const char* refused : {"---", "Geramy's PC", "a;b", "line\nbreak", "tab\there"}) {
        EXPECT_EQ(ln_set_device_name(client.c, refused), LN_ERR_REJECTED) << refused;
    }
    EXPECT_EQ(ln_set_device_name(client.c, std::string(65, 'a').c_str()), LN_ERR_REJECTED);
    EXPECT_EQ(ln_set_device_name(client.c, std::string(64, 'a').c_str()), LN_OK);
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
    const std::string token = "lnk_" + std::string(64, 'a');
    EXPECT_EQ(ln_invite_accept(client.c, token.c_str(), &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    ln_free(out);
    out = nullptr;
    EXPECT_EQ(ln_invite_accept(client.c, "12345678", &out), LN_ERR_CONNECT)
        << "an 8-digit code goes to the server as the invite";
    ASSERT_NE(out, nullptr);
    ln_free(out);
    out = nullptr;
    // Neither a code nor a token: refused before any request, with the reason.
    for (const char* malformed : {"lnk_x", "1234567", "123456789", "1234567a", ""}) {
        EXPECT_EQ(ln_invite_accept(client.c, malformed, &out), LN_ERR_REJECTED) << malformed;
        ASSERT_NE(out, nullptr);
        EXPECT_NE(std::string(out).find("error"), std::string::npos);
        ln_free(out);
        out = nullptr;
    }
    EXPECT_EQ(ln_set_link_token(client.c, "12345678"), LN_OK);
    EXPECT_EQ(ln_set_link_token(client.c, token.c_str()), LN_OK);
    EXPECT_EQ(ln_set_link_token(client.c, ""), LN_OK);
    EXPECT_EQ(ln_set_link_token(client.c, "1234-5678"), LN_ERR_REJECTED);
    EXPECT_EQ(ln_set_link_token(client.c, "lnk_x"), LN_ERR_REJECTED);
    EXPECT_EQ(ln_memberships_list(client.c, &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    ln_free(out);
    out = nullptr;
    EXPECT_EQ(ln_move_node(client.c, "n", "g", &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    ln_free(out);
}

// Account deletion: argument checks, the identity requirement, and the
// inactive-mesh result. No request leaves without an identity to sign with.
TEST(SdkCapiMesh, AccountDeletionChecksArgumentsAndNeedsAnIdentity) {
    char* out = nullptr;
    EXPECT_EQ(ln_account_delete(nullptr, &out), LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_account_delete(client.c, nullptr), LN_ERR_NULL_ARG);

    EXPECT_EQ(ln_account_delete(client.c, &out), LN_ERR_NO_IDENTITY);
    ASSERT_NE(out, nullptr);
    EXPECT_NE(std::string(out).find("error"), std::string::npos);
    ln_free(out);
    out = nullptr;

    ln_identity_t* identity = ln_identity_generate();
    ASSERT_NE(identity, nullptr);
    ASSERT_EQ(ln_set_identity(client.c, identity), LN_OK);
    ln_identity_destroy(identity);
    EXPECT_EQ(ln_account_delete(client.c, &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    EXPECT_NE(std::string(out).find("error"), std::string::npos);
    ln_free(out);
}

namespace {
void count_session_move(char* event_json, void* user) {
    ln_free(event_json);
    ++*static_cast<int*>(user);
}
}  // namespace

// The session-move callback: argument checks, and set/clear without a move
// in flight. Before any join there is no session to move, so the callback
// never runs.
TEST(SdkCapiMesh, SessionMovedCallbackIsSetAndCleared) {
    int calls = 0;
    EXPECT_EQ(ln_set_session_moved_callback(nullptr, count_session_move, &calls),
              LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_set_session_moved_callback(client.c, count_session_move, &calls), LN_OK);
    EXPECT_EQ(ln_set_session_moved_callback(client.c, nullptr, nullptr), LN_OK);
    EXPECT_EQ(ln_set_session_moved_callback(client.c, count_session_move, &calls), LN_OK);
    char* status = nullptr;
    ASSERT_EQ(ln_mesh_status(client.c, &status), LN_OK);
    ASSERT_NE(status, nullptr);
    EXPECT_NE(std::string(status).find("\"needs_rejoin\":false"), std::string::npos);
    ln_free(status);
    EXPECT_EQ(calls, 0);
}
