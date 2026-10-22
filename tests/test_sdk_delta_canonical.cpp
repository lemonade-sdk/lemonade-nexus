// The SDK and the server must encode a tree delta identically: the server
// verifies the SDK's signature over its own canonical form, so any field one
// side omits makes every SDK-signed delta fail verification.

#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexusSDK/Types.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

TEST(SdkDeltaCanonical, SdkAndServerEncodeTheSameDelta) {
    lnsdk::TreeNode node;
    node.id = "node-abc";
    node.parent_id = "customer-abc";
    node.type = lnsdk::NodeType::Endpoint;
    node.hostname = "laptop";
    node.tunnel_ip = "10.64.0.9/32";
    node.mgmt_pubkey = "ed25519:AAAA";
    node.mesh_pubkey = "BBBB";
    node.endpoint_identifier = "infer-abcd-efgh";
    node.cpu_id = "cpu-1";
    node.net_mac = "aa:bb:cc:dd:ee:ff";
    node.is_inference = true;
    node.assignments = {{"ed25519:AAAA", {"read", "edit_node"}}};
    node.region = "us-west";
    node.reputation_score = 1.0f;

    lnsdk::TreeDelta sdk_delta;
    sdk_delta.operation = "update_node";
    sdk_delta.target_node_id = node.id;
    sdk_delta.node_data = node;
    sdk_delta.signer_pubkey = "ed25519:AAAA";
    sdk_delta.timestamp = 1792700000;

    // The server reads what the SDK sends.
    const nlohmann::json wire = sdk_delta;
    nexus::tree::TreeDelta server_delta;
    ASSERT_NO_THROW(server_delta = wire.get<nexus::tree::TreeDelta>());
    EXPECT_TRUE(server_delta.node_data.is_inference);
    EXPECT_EQ(server_delta.node_data.endpoint_identifier, "infer-abcd-efgh");

    EXPECT_EQ(lnsdk::canonical_delta_json(sdk_delta),
              nexus::tree::canonical_delta_json(server_delta));
}

TEST(SdkDeltaCanonical, SdkReadsTheTierFromServerJson) {
    nexus::tree::TreeNode server_node;
    server_node.id = "node-1";
    server_node.type = nexus::tree::NodeType::Endpoint;
    server_node.is_inference = true;
    const nlohmann::json j = server_node;
    const auto sdk_node = j.get<lnsdk::TreeNode>();
    EXPECT_TRUE(sdk_node.is_inference);
}
