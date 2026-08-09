import 'dart:convert';

import 'package:lon/lon.dart';
import 'package:test/test.dart';
import 'package:toto/toto.dart';

void main() {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  final now = DateTime.utc(2026, 8, 9, 12);

  Future<RunResult> run(
    List<String> arguments, {
    String stdinValue = '',
    Map<String, String> environment = const <String, String>{},
    DateTime Function()? clock,
  }) async {
    final output = StringBuffer();
    final errors = StringBuffer();
    final exitCode = await runToto(
      arguments,
      input: Stream<List<int>>.value(utf8.encode(stdinValue)),
      output: output,
      errorOutput: errors,
      environment: environment,
      now: clock ?? () => now,
    );
    return RunResult(exitCode, output.toString(), errors.toString());
  }

  group('code', () {
    test('generates deterministic TOTP text with the short command', () async {
      final result = await run(<String>[
        'code',
        '--secret',
        secret,
        '--digits',
        '8',
        '--at',
        '59',
      ]);
      expect(result.exitCode, 0);
      expect(result.stdout, '94287082\n');
      expect(result.stderr, isEmpty);
    });

    test('generate alias emits the canonical JSON command name', () async {
      final result = await run(<String>[
        'generate',
        '--format',
        'json',
        '--secret',
        secret,
        '--at',
        '59',
      ]);
      final data = jsonDecode(result.stdout) as Map<String, Object?>;
      expect(data['command'], 'code');
      expect(data['type'], 'totp');
    });

    test('supports HOTP URI input, counter override, and LON output', () async {
      final uri = 'otpauth://hotp/Acme:alice?secret=$secret&counter=0';
      final result = await run(<String>[
        'code',
        '--format=lon',
        '--uri-env',
        'OTP_URI',
        '--counter',
        '1',
      ], environment: <String, String>{
        'OTP_URI': uri
      });
      final data = lon.decode(result.stdout.trim()) as Map<Object?, Object?>;
      expect(result.exitCode, 0);
      expect(data['command'], 'code');
      expect(data['type'], 'hotp');
      expect(data['counter'], 1);
      expect(result.stderr, isEmpty);
    });
  });

  group('check', () {
    test('verify alias returns 0 for valid and canonical command output',
        () async {
      final result = await run(<String>[
        'verify',
        '94287082',
        '--format',
        'json',
        '--secret',
        secret,
        '--digits',
        '8',
        '--at',
        '59',
      ]);
      final data = jsonDecode(result.stdout) as Map<String, Object?>;
      expect(result.exitCode, 0);
      expect(data['command'], 'check');
      expect(data['valid'], isTrue);
    });

    test('returns 1 and false for a well-formed mismatch', () async {
      final result = await run(<String>[
        'check',
        '00000000',
        '--secret',
        secret,
        '--digits',
        '8',
        '--at',
        '59',
      ]);
      expect(result.exitCode, 1);
      expect(result.stdout, 'false\n');
      expect(result.stderr, isEmpty);
    });

    test('returns 2 for a malformed code', () async {
      final result = await run(<String>[
        'check',
        '12x456',
        '--secret',
        secret,
        '--at',
        '59',
      ]);
      expect(result.exitCode, 2);
      expect(result.stdout, isEmpty);
      expect(result.stderr, startsWith('error[invalid_option]:'));
    });

    test('reads a secret from stdin', () async {
      final result = await run(<String>[
        'check',
        '94287082',
        '--secret-stdin',
        '--digits',
        '8',
        '--at',
        '59',
      ], stdinValue: '$secret\n');
      expect(result.exitCode, 0);
      expect(result.stdout, 'true\n');
    });
  });

  group('key and uri', () {
    test('secret alias emits canonical key output', () async {
      final result = await run(<String>[
        'secret',
        '--format',
        'json',
        '--length',
        '32',
      ]);
      final data = jsonDecode(result.stdout) as Map<String, Object?>;
      expect(result.exitCode, 0);
      expect(data['command'], 'key');
      expect(data['secret'], matches(r'^[A-Z2-7]{32}$'));
      expect(data['entropyBits'], 160);
    });

    test('creates TOTP and HOTP provisioning URIs', () async {
      final totp = await run(<String>[
        'uri',
        '--secret',
        secret,
        '--issuer',
        'Acme',
        '--account',
        'alice@example.com',
      ]);
      expect(totp.exitCode, 0);
      expect(
          totp.stdout, startsWith('otpauth://totp/Acme:alice%40example.com'));

      final hotp = await run(<String>[
        'uri',
        '--format',
        'json',
        '--secret',
        secret,
        '--type',
        'hotp',
        '--counter',
        '7',
        '--account',
        'alice',
      ]);
      final data = jsonDecode(hotp.stdout) as Map<String, Object?>;
      expect(data['type'], 'hotp');
      expect(data['counter'], 7);
    });
  });

  group('argument and format errors', () {
    test('rejects a repeated valid format with a structured error', () async {
      final result = await run(<String>[
        'code',
        '--format',
        'json',
        '--format=json',
        '--secret',
        secret,
        '--at',
        '59',
      ]);
      expect(result.exitCode, 2);
      expect(result.stdout, isEmpty);
      final data = jsonDecode(result.stderr) as Map<String, Object?>;
      expect(data['status'], 'error');
      expect(
        (data['error'] as Map<String, Object?>)['code'],
        'invalid_arguments',
      );
    });

    test('rejects a repeated single-value option', () async {
      final result = await run(<String>[
        'code',
        '--secret',
        secret,
        '--secret=$secret',
        '--at',
        '59',
      ]);
      expect(result.exitCode, 2);
      expect(result.stdout, isEmpty);
      expect(
        result.stderr,
        'error[invalid_arguments]: Invalid arguments.\n',
      );
    });

    test('conflicting, invalid, or missing format falls back to text',
        () async {
      final cases = <List<String>>[
        <String>['code', '--format', 'json', '--format', 'lon'],
        <String>['code', '--format', 'yaml'],
        <String>['code', '--format'],
      ];
      for (final arguments in cases) {
        final result = await run(arguments);
        expect(result.exitCode, 2, reason: arguments.toString());
        expect(
          result.stderr,
          'error[invalid_arguments]: Invalid arguments.\n',
          reason: arguments.toString(),
        );
      }
    });

    test('does not scan format tokens after the option delimiter', () async {
      final result = await run(<String>[
        'code',
        '--secret',
        secret,
        '--',
        '--format',
        'json',
      ]);
      expect(result.exitCode, 2);
      expect(result.stdout, isEmpty);
      expect(
        result.stderr,
        'error[invalid_arguments]: Invalid arguments.\n',
      );
    });

    test('rejects URI-owned and type-incompatible options', () async {
      final uri = 'otpauth://totp/Acme:alice?secret=$secret';
      for (final extra in <List<String>>[
        <String>['--type', 'totp'],
        <String>['--digits', '6'],
        <String>['--algorithm', 'sha1'],
        <String>['--period', '30'],
        <String>['--counter', '0'],
      ]) {
        final result = await run(<String>[
          'code',
          '--uri',
          uri,
          ...extra,
        ]);
        expect(result.exitCode, 2, reason: extra.toString());
        expect(result.stderr, startsWith('error[conflicting_options]:'));
      }
    });

    test('rejects URI-owned options before reading or parsing the URI',
        () async {
      for (final arguments in <List<String>>[
        <String>['code', '--uri', 'not-a-uri', '--type', 'totp'],
        <String>['code', '--uri-env', 'MISSING', '--digits', '6'],
        <String>['code', '--uri-stdin', '--algorithm', 'sha1'],
      ]) {
        final result = await run(arguments);
        expect(result.exitCode, 2, reason: arguments.toString());
        expect(
          result.stderr,
          startsWith('error[conflicting_options]:'),
          reason: arguments.toString(),
        );
      }
    });

    test('validates known static options before reading credential stdin',
        () async {
      final cases = <({List<String> arguments, String errorCode})>[
        (
          arguments: <String>[
            'code',
            '--type',
            'hotp',
            '--secret-stdin',
          ],
          errorCode: 'missing_option',
        ),
        (
          arguments: <String>[
            'code',
            '--type',
            'hotp',
            '--secret-stdin',
            '--counter',
            '0',
            '--at',
            '59',
          ],
          errorCode: 'conflicting_options',
        ),
        (
          arguments: <String>[
            'code',
            '--secret-stdin',
            '--counter',
            '0',
          ],
          errorCode: 'conflicting_options',
        ),
        (
          arguments: <String>['uri', '--secret-stdin'],
          errorCode: 'missing_option',
        ),
        (
          arguments: <String>[
            'uri',
            '--type',
            'hotp',
            '--secret-stdin',
            '--period',
            '30',
            '--account',
            'alice',
          ],
          errorCode: 'conflicting_options',
        ),
      ];
      for (final item in cases) {
        final result = await run(item.arguments);
        expect(result.exitCode, 2, reason: item.arguments.toString());
        expect(
          result.stderr,
          startsWith('error[${item.errorCode}]:'),
          reason: item.arguments.toString(),
        );
      }
    });
  });

  group('help and version', () {
    test('documents global format, credential values, and check positional',
        () async {
      final root = await run(<String>['--help']);
      expect(root.stdout, contains('--format=<FORMAT>'));
      expect(root.stdout, contains('text, json, or lon'));

      final code = await run(<String>['code', '--help']);
      expect(code.stdout, contains('--secret-env=<NAME>'));
      expect(code.stdout, contains('--uri-stdin'));
      expect(code.stdout, contains('--format=<FORMAT>'));

      final check = await run(<String>['check', '--help']);
      expect(check.stdout, contains('Usage: toto check <code> [options]'));
      expect(check.stdout, contains('--window=<STEPS>'));
    });

    test('remain human-readable when format is json or lon', () async {
      for (final arguments in <List<String>>[
        <String>['--help', '--format', 'json'],
        <String>['code', '--help', '--format', 'lon'],
        <String>['--version', '--format', 'json'],
      ]) {
        final result = await run(arguments);
        expect(result.exitCode, 0);
        expect(result.stderr, isEmpty);
        expect(result.stdout, isNot(startsWith('{')));
        expect(result.stdout, isNot(startsWith('[')));
      }
    });
  });
}

final class RunResult {
  const RunResult(this.exitCode, this.stdout, this.stderr);

  final int exitCode;
  final String stdout;
  final String stderr;
}
