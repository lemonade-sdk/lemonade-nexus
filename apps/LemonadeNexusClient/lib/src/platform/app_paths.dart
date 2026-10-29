/// Cross-platform application data paths (Application Support on macOS, AppData
/// on Windows, the XDG data dir on Linux).
library;

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

class AppPaths {
  static Future<Directory> supportDir() async {
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir;
  }

  /// The legacy plaintext identity file (`ln_identity_save` format). The
  /// device identity now lives in the SDK's per-user identity store; a file
  /// found here is imported once and deleted (see `device_identity.dart`).
  static Future<String> identityFilePath() async {
    final dir = await supportDir();
    return p.join(dir.path, 'identity.json');
  }
}
