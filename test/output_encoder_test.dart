import 'dart:convert';

import 'package:lon/lon.dart';
import 'package:test/test.dart';
import 'package:toto/src/cli/cli_failure.dart';
import 'package:toto/src/output/output_encoder.dart';

void main() {
  const encoder = OutputEncoder();

  group('success output', () {
    final checkResult = <String, Object?>{
      'schemaVersion': 1,
      'status': 'ok',
      'command': 'check',
      'type': 'hotp',
      'valid': false,
      'algorithm': 'sha1',
      'digits': 6,
      'counter': 4,
      'window': 0,
      'matchedCounter': null,
      'nextCounter': null,
    };

    test('text is the scalar plus exactly one newline', () {
      expect(
        encoder.success(
          format: OutputFormat.text,
          text: 'false',
          data: checkResult,
        ),
        'false\n',
      );
    });

    test('json is compact, ordered, and newline terminated', () {
      final output = encoder.success(
        format: OutputFormat.json,
        text: 'false',
        data: checkResult,
      );

      expect(output, '${jsonEncode(checkResult)}\n');
      expect(output.split('\n'), hasLength(2));
      expect(jsonDecode(output), checkResult);
    });

    test('lon is canonical, lossless, and newline terminated', () {
      final output = encoder.success(
        format: OutputFormat.lon,
        text: 'false',
        data: checkResult,
      );

      expect(output, '${lon.encode(checkResult)}\n');
      expect(output.split('\n'), hasLength(2));
      expect(lon.decode(output.trimRight()), checkResult);
    });

    test('all command result maps preserve their declared field order', () {
      final results = <Map<String, Object?>>[
        <String, Object?>{
          'schemaVersion': 1,
          'status': 'ok',
          'command': 'code',
          'type': 'totp',
          'code': '123456',
          'algorithm': 'sha1',
          'digits': 6,
          'period': 30,
          'at': '2026-08-09T00:00:00Z',
          'validFor': 30,
        },
        <String, Object?>{
          'schemaVersion': 1,
          'status': 'ok',
          'command': 'code',
          'type': 'hotp',
          'code': '755224',
          'algorithm': 'sha1',
          'digits': 6,
          'counter': 0,
        },
        <String, Object?>{
          'schemaVersion': 1,
          'status': 'ok',
          'command': 'check',
          'type': 'totp',
          'valid': true,
          'algorithm': 'sha1',
          'digits': 6,
          'period': 30,
          'at': '2026-08-09T00:00:00Z',
          'window': 1,
          'matchedOffset': 0,
          'matchedAt': '2026-08-09T00:00:00Z',
        },
        checkResult,
        <String, Object?>{
          'schemaVersion': 1,
          'status': 'ok',
          'command': 'key',
          'secret': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
          'length': 32,
          'entropyBits': 160,
        },
        <String, Object?>{
          'schemaVersion': 1,
          'status': 'ok',
          'command': 'uri',
          'type': 'totp',
          'uri': 'otpauth://totp/Acme:alice?secret=ABC',
          'algorithm': 'sha1',
          'digits': 6,
          'issuer': 'Acme',
          'account': 'alice',
          'period': 30,
        },
        <String, Object?>{
          'schemaVersion': 1,
          'status': 'ok',
          'command': 'uri',
          'type': 'hotp',
          'uri': 'otpauth://hotp/Acme:alice?secret=ABC&counter=0',
          'algorithm': 'sha1',
          'digits': 6,
          'issuer': 'Acme',
          'account': 'alice',
          'counter': 0,
        },
      ];

      for (final result in results) {
        final jsonOutput = encoder.success(
          format: OutputFormat.json,
          text: 'scalar',
          data: result,
        );
        final lonOutput = encoder.success(
          format: OutputFormat.lon,
          text: 'scalar',
          data: result,
        );
        expect(jsonOutput, '${jsonEncode(result)}\n');
        expect(lonOutput, '${lon.encode(result)}\n');
      }
    });
  });

  group('failure output', () {
    const failure = CliFailure(
      code: 'invalid_option',
      message: 'Invalid option.',
      details: <String, Object?>{
        'option': 'digits',
        'expected': 'digits:6..8',
      },
    );

    test('text uses a stable single-line diagnostic', () {
      expect(
        encoder.failure(format: OutputFormat.text, failure: failure),
        'error[invalid_option]: Invalid option.\n',
      );
    });

    test('json uses the stable error envelope', () {
      expect(
        encoder.failure(format: OutputFormat.json, failure: failure),
        '${jsonEncode(failure.toData())}\n',
      );
    });

    test('lon uses the same stable error envelope', () {
      expect(
        encoder.failure(format: OutputFormat.lon, failure: failure),
        '${lon.encode(failure.toData())}\n',
      );
    });
  });

  group('format parsing', () {
    test('accepts only the three canonical lower-case values', () {
      expect(OutputFormat.parse('text'), OutputFormat.text);
      expect(OutputFormat.parse('json'), OutputFormat.json);
      expect(OutputFormat.parse('lon'), OutputFormat.lon);
      expect(() => OutputFormat.parse('JSON'), throwsA(isA<CliFailure>()));
    });
  });
}
