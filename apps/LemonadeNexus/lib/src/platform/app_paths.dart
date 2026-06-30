/// Cross-platform application data paths (Application Support on macOS, AppData
/// on Windows, the XDG data dir on Linux).

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

class AppPaths {
  static Future<Directory> supportDir() async {
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir;
  }

  /// File holding the Ed25519 identity (written via the SDK's ln_identity_save).
  static Future<String> identityFilePath() async {
    final dir = await supportDir();
    return p.join(dir.path, 'identity.json');
  }
}
