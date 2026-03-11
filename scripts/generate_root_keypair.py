#!/usr/bin/env python3
"""
Generate an Ed25519 root management keypair for Lemonade-Nexus.

The root keypair is the top of the trust hierarchy:
  - The PUBLIC key is passed to every server via --root-pubkey (hex)
  - The PRIVATE key stays on the root management node to sign server certificates
    via --enroll-server <pubkey> <server-id>

Usage:
    python3 generate_root_keypair.py
    python3 generate_root_keypair.py --output /path/to/root_keypair.json

Requirements:
    pip3 install pynacl
"""

import argparse
import json
import os
import sys
import time

try:
    import nacl.signing
    import nacl.encoding
except ImportError:
    print("Error: PyNaCl is required. Install with: pip3 install pynacl", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate Lemonade-Nexus root Ed25519 keypair")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Save keypair to JSON file (private key included — keep secure!)")
    args = parser.parse_args()

    # Generate Ed25519 keypair
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Encode in both formats used by the project
    privkey_b64 = signing_key.encode(nacl.encoding.Base64Encoder).decode()
    pubkey_b64 = verify_key.encode(nacl.encoding.Base64Encoder).decode()
    pubkey_hex = verify_key.encode(nacl.encoding.HexEncoder).decode()

    keypair_data = {
        "type": "lemonade-nexus_root_keypair",
        "created_at": int(time.time()),
        "public_key_hex": pubkey_hex,
        "public_key_base64": pubkey_b64,
        "private_key_base64": privkey_b64,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(keypair_data, f, indent=2)
            f.write("\n")
        os.chmod(args.output, 0o600)
        print(f"Keypair saved to: {args.output} (mode 0600)")
        print()

    print("=" * 68)
    print("  Lemonade-Nexus Root Management Keypair")
    print("=" * 68)
    print()
    print("PUBLIC KEY (hex) — pass to every server:")
    print(f"  {pubkey_hex}")
    print()
    print("PUBLIC KEY (base64):")
    print(f"  {pubkey_b64}")
    print()
    print("PRIVATE KEY (base64) — keep secret, stays on root node only:")
    print(f"  {privkey_b64}")
    print()
    print("-" * 68)
    print("Configuration:")
    print("-" * 68)
    print()
    print("1. On the ROOT server (the one that enrolls other servers):")
    print("   The root identity is auto-generated on first run.")
    print("   Just start the server normally — it creates data/identity/.")
    print()
    print("   To use this key instead of auto-generated, place it in")
    print("   the data/identity/ directory before first start, or set:")
    print(f"     export SP_ROOT_PUBKEY={pubkey_hex}")
    print()
    print("2. On EVERY server in the mesh:")
    print(f"   --root-pubkey {pubkey_hex}")
    print("   or in lemonade-nexus.env:")
    print(f"     SP_ROOT_PUBKEY={pubkey_hex}")
    print("   or in lemonade-nexus.json:")
    print(f'     "root_pubkey": "{pubkey_hex}"')
    print()
    print("3. To enroll a new server (run on root server):")
    print("   ./lemonade-nexus --enroll-server <server-pubkey-hex> <server-id>")
    print()
    print("=" * 68)


if __name__ == "__main__":
    main()
