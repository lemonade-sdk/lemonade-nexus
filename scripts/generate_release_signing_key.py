#!/usr/bin/env python3
"""
Generate an Ed25519 release signing keypair for Lemonade-Nexus binary attestation.

Usage:
    python3 generate_release_signing_key.py

Output:
    - Prints the private key (base64) — store this as GitHub Actions secret RELEASE_SIGNING_KEY
    - Prints the public key (base64) — store this as GitHub Actions variable RELEASE_SIGNING_PUBKEY
      and configure it in lemonade-nexus.json as "release_signing_pubkey"

Requirements:
    pip3 install pynacl
"""

import nacl.signing
import nacl.encoding

def main():
    # Generate a new Ed25519 signing key
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Encode as base64
    privkey_b64 = signing_key.encode(nacl.encoding.Base64Encoder).decode()
    pubkey_b64 = verify_key.encode(nacl.encoding.Base64Encoder).decode()

    print("=" * 60)
    print("Lemonade-Nexus Release Signing Key Generated")
    print("=" * 60)
    print()
    print("PRIVATE KEY (base64) — GitHub Actions secret: RELEASE_SIGNING_KEY")
    print(f"  {privkey_b64}")
    print()
    print("PUBLIC KEY (base64) — GitHub Actions variable: RELEASE_SIGNING_PUBKEY")
    print(f"  {pubkey_b64}")
    print()
    print("Add to lemonade-nexus.json:")
    print(f'  "release_signing_pubkey": "{pubkey_b64}"')
    print()
    print("Or via CLI:")
    print(f"  ./LemonadeNexusApp --release-signing-pubkey {pubkey_b64}")
    print()
    print("Or via environment:")
    print(f"  export SP_RELEASE_SIGNING_PUBKEY={pubkey_b64}")
    print()
    print("IMPORTANT: Keep the private key secret! Only store it in GitHub Actions secrets.")
    print("=" * 60)

if __name__ == "__main__":
    main()
