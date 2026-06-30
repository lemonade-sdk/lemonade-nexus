/// Base exception for Lemonade API errors.
class LemonadeApiException implements Exception {
  final String message;
  final String? endpoint;
  final Object? cause;

  const LemonadeApiException(this.message, {this.endpoint, this.cause});

  @override
  String toString() => 'LemonadeApiException${endpoint != null ? " ($endpoint)" : ""}: $message';
}

class UnauthorizedException extends LemonadeApiException {
  UnauthorizedException(super.message, {super.endpoint, super.cause});
}

class NotFoundException extends LemonadeApiException {
  NotFoundException(super.message, {super.endpoint, super.cause});
}

class ModelMismatchException extends LemonadeApiException {
  ModelMismatchException(super.message, {super.endpoint, super.cause});
}

class ServerException extends LemonadeApiException {
  final int? statusCode;
  ServerException(super.message, {this.statusCode, super.endpoint, super.cause});

  @override
  String toString() => 'ServerException${endpoint != null ? " ($endpoint)" : ""}: $message (HTTP ${statusCode ?? "?"})';
}
