// C ABI contract for the mesh and node-role calls an embedding application
// (the Lemonade server) uses: argument checks and inactive-mesh behavior.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <gtest/gtest.h>

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
