#!/usr/bin/env python3
"""
Generate an Ed25519 keypair for Lemonade-Nexus (offline/backup use).

NOTE: the server cannot import an externally generated keypair. The actual
mesh root is the genesis server's own identity, created and printed by
`./lemonade-nexus --first-run` — that identity pubkey (hex) is what every
server passes as --root-pubkey, and its private key (data/identity/keypair.enc,
machine-bound) is what signs server certificates during --enroll-server.

Use this script only to pre-generate key material for offline storage or
future import/rotation tooling.

Usage:
    python3 generate_root_keypair.py                 # saves ./root_keypair.json
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
    parser.add_argument("--output", "-o", type=str, default="root_keypair.json",
                        help="Save keypair to JSON file (private key included — keep secure!) "
                             "(default: %(default)s in the current directory)")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite the output file if it already exists")
    args = parser.parse_args()

    out_path = os.path.abspath(args.output)
    if os.path.exists(out_path) and not args.force:
        print(f"Error: {out_path} already exists — refusing to overwrite a root keypair.",
              file=sys.stderr)
        print("Pass --force to overwrite, or -o <path> for a different location.",
              file=sys.stderr)
        sys.exit(1)

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

    with open(out_path, "w") as f:
        json.dump(keypair_data, f, indent=2)
        f.write("\n")
    os.chmod(out_path, 0o600)
    print(f"Keypair saved to: {out_path} (mode 0600)")
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
    print("NOTE — offline/backup keypair only:")
    print("  The server cannot import an externally generated keypair. The mesh")
    print("  root is the GENESIS server's own identity, created and printed by:")
    print("    ./lemonade-nexus --first-run")
    print("  Every server passes THAT identity pubkey (hex) as --root-pubkey.")
    print("  Passing this script's pubkey as --root-pubkey instead would make")
    print("  peers reject every certificate the genesis signs.")
    print()
    print("To enroll a new server (run on the genesis server):")
    print("  ./lemonade-nexus --enroll-server '<gossip-pubkey-base64>' <server-id>")
    print("  (the joining server prints its gossip pubkey during --first-run)")
    print()
    print("=" * 68)


if __name__ == "__main__":
    main()
