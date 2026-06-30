/// Configuration for a connected Lemonade server.
library;

class ServerConfig {
  final String baseUrl;
  final String? apiKey;
  final String name;

  ServerConfig({
    required this.baseUrl,
    this.apiKey,
    required this.name,
  });

  /// Returns the base URL normalized for API use.
  String get apiUrl {
    String url = baseUrl;
    while (url.endsWith('/')) {
      url = url.substring(0, url.length - 1);
    }
    if (url.endsWith('/api/v1')) return url;
    if (url.endsWith('/v1')) return url;
    if (url.endsWith('/api')) {
      return '$url/v1';
    }
    return '$url/api/v1';
  }

  Map<String, dynamic> toJson() => {
        'baseUrl': baseUrl,
        'apiKey': apiKey,
        'name': name,
      };

  factory ServerConfig.fromJson(Map<String, dynamic> json) => ServerConfig(
        baseUrl: json['baseUrl'] as String? ?? '',
        apiKey: json['apiKey'] as String?,
        name: json['name'] as String? ?? '',
      );

  @override
  String toString() => name;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ServerConfig &&
          runtimeType == other.runtimeType &&
          baseUrl == other.baseUrl &&
          apiKey == other.apiKey &&
          name == other.name;

  @override
  int get hashCode => baseUrl.hashCode ^ apiKey.hashCode ^ name.hashCode;
}
