/// Dart API for the Lemonade Nexus client SDK.
///
/// [LemonadeNexusSdk] wraps the C API. [NexusWorker] runs it on a background
/// isolate, so blocking network calls never stall the UI.
///
/// DNS server discovery is a separate library,
/// `package:lemonade_nexus_sdk/dns_discovery.dart`, and the raw bindings are
/// `package:lemonade_nexus_sdk/ffi_bindings.dart`.
library;

export 'src/sdk.dart';
export 'src/nexus_worker.dart';
