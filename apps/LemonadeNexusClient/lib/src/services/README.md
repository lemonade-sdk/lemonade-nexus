# Services

App-specific services that sit between the UI and the SDK.

| File | Responsibility |
|------|----------------|
| `dns_discovery.dart` | Regional DNS discovery of mesh servers (SEIP records, `_config` TXT, health probing, scoring) |
| `passkey_manager.dart` | WebAuthn passkey registration and assertion flows for client authentication |
