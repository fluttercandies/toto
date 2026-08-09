import 'dart:convert';

import 'package:lon/lon.dart';

import '../cli/cli_failure.dart';

enum OutputFormat {
  text,
  json,
  lon;

  static OutputFormat parse(String value) => switch (value) {
        'text' => OutputFormat.text,
        'json' => OutputFormat.json,
        'lon' => OutputFormat.lon,
        _ => throw const CliFailure(
            code: 'invalid_option',
            message: 'Invalid option.',
            details: <String, Object?>{
              'option': 'format',
              'expected': 'enum:text|json|lon',
            },
          ),
      };
}

final class OutputEncoder {
  const OutputEncoder();

  String success({
    required OutputFormat format,
    required String text,
    required Map<String, Object?> data,
  }) =>
      '${_encode(format: format, text: text, data: data)}\n';

  String failure({
    required OutputFormat format,
    required CliFailure failure,
  }) =>
      '${_encode(
        format: format,
        text: 'error[${failure.code}]: ${failure.message}',
        data: failure.toData(),
      )}\n';

  String _encode({
    required OutputFormat format,
    required String text,
    required Map<String, Object?> data,
  }) =>
      switch (format) {
        OutputFormat.text => text,
        OutputFormat.json => jsonEncode(data),
        OutputFormat.lon => lon.encode(data),
      };
}
