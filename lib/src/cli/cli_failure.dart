final class CliFailure implements Exception {
  const CliFailure({
    required this.code,
    required this.message,
    this.details = const <String, Object?>{},
    this.exitCode = 2,
  });

  final String code;
  final String message;
  final Map<String, Object?> details;
  final int exitCode;

  Map<String, Object?> toData() => <String, Object?>{
        'schemaVersion': 1,
        'status': 'error',
        'error': <String, Object?>{
          'code': code,
          'message': message,
          'details': details,
        },
      };
}
