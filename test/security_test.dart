import 'dart:convert';

import 'package:test/test.dart';
import 'package:toto/toto.dart';

void main() {
  const validSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const sentinel = 'TOTO_PRIVATE_SENTINEL_9f41c7';

  Future<String> failingOutput(
    List<String> arguments, {
    String stdinValue = '',
    Map<String, String> environment = const <String, String>{},
    DateTime Function()? now,
  }) async {
    final output = StringBuffer();
    final errors = StringBuffer();
    final code = await runToto(
      arguments,
      input: Stream<List<int>>.value(utf8.encode(stdinValue)),
      output: output,
      errorOutput: errors,
      environment: environment,
      now: now ?? () => DateTime.utc(2026, 8, 9),
    );
    expect(code, anyOf(2, 70));
    expect(output.toString(), isEmpty);
    return errors.toString();
  }

  Future<void> expectRedactedFailure({
    required String expectedCode,
    required List<String> arguments,
    String stdinValue = '',
    Map<String, String> environment = const <String, String>{},
    DateTime Function()? now,
  }) async {
    final errors = await failingOutput(
      arguments,
      stdinValue: stdinValue,
      environment: environment,
      now: now,
    );
    expect(errors, isNot(contains(sentinel)), reason: expectedCode);
    final data = jsonDecode(errors) as Map<String, Object?>;
    final error = data['error']! as Map<String, Object?>;
    expect(error['code'], expectedCode);
  }

  test('redacts every stable error category and credential source', () async {
    await expectRedactedFailure(
      expectedCode: 'unknown_command',
      arguments: <String>[sentinel, '--format', 'json'],
    );
    await expectRedactedFailure(
      expectedCode: 'invalid_arguments',
      arguments: <String>[
        'code',
        '--unknown=$sentinel',
        '--format',
        'json',
      ],
    );
    await expectRedactedFailure(
      expectedCode: 'missing_argument',
      arguments: <String>[
        'check',
        '--secret',
        validSecret,
        '--format',
        'json',
      ],
      environment: const <String, String>{sentinel: sentinel},
    );
    await expectRedactedFailure(
      expectedCode: 'missing_option',
      arguments: <String>['code', '--format', 'json'],
      environment: const <String, String>{sentinel: sentinel},
    );
    await expectRedactedFailure(
      expectedCode: 'conflicting_options',
      arguments: <String>[
        'code',
        '--secret',
        validSecret,
        '--secret-env',
        sentinel,
        '--format',
        'json',
      ],
      environment: const <String, String>{sentinel: sentinel},
    );
    for (final arguments in <List<String>>[
      <String>[
        'code',
        '--secret',
        validSecret,
        '--at',
        sentinel,
        '--format',
        'json',
      ],
      <String>[
        'code',
        '--type',
        'hotp',
        '--secret',
        validSecret,
        '--counter',
        sentinel,
        '--format',
        'json',
      ],
    ]) {
      await expectRedactedFailure(
        expectedCode: 'invalid_option',
        arguments: arguments,
      );
    }
    await expectRedactedFailure(
      expectedCode: 'missing_environment',
      arguments: <String>[
        'code',
        '--secret-env',
        sentinel,
        '--format',
        'json',
      ],
    );
    for (final source in <String>['secret-env', 'uri-env']) {
      await expectRedactedFailure(
        expectedCode: 'empty_environment',
        arguments: <String>[
          'code',
          '--$source',
          sentinel,
          '--format',
          'json',
        ],
        environment: const <String, String>{sentinel: ''},
      );
    }
    await expectRedactedFailure(
      expectedCode: 'empty_stdin',
      arguments: <String>[
        'code',
        '--secret-stdin',
        '--at',
        sentinel,
        '--format',
        'json',
      ],
      stdinValue: '\n',
    );

    final oversizedSecret = '${List<String>.filled(4097, 'A').join()}$sentinel';
    await expectRedactedFailure(
      expectedCode: 'input_too_large',
      arguments: <String>[
        'code',
        '--secret',
        oversizedSecret,
        '--format',
        'json',
      ],
    );
    final oversizedUri =
        'otpauth://totp/${List<String>.filled(16384, 'A').join()}$sentinel';
    await expectRedactedFailure(
      expectedCode: 'input_too_large',
      arguments: <String>[
        'code',
        '--uri',
        oversizedUri,
        '--format',
        'json',
      ],
    );
    await expectRedactedFailure(
      expectedCode: 'input_too_large',
      arguments: <String>[
        'code',
        '--secret-stdin',
        '--format',
        'json',
      ],
      stdinValue: '${List<String>.filled(16385, 'A').join()}$sentinel',
    );

    for (final source in <String>['direct', 'environment', 'stdin']) {
      await expectRedactedFailure(
        expectedCode: 'invalid_secret',
        arguments: switch (source) {
          'direct' => <String>[
              'code',
              '--secret',
              sentinel,
              '--format',
              'json',
            ],
          'environment' => <String>[
              'code',
              '--secret-env',
              'PRIVATE_SECRET',
              '--format',
              'json',
            ],
          _ => <String>[
              'code',
              '--secret-stdin',
              '--format',
              'json',
            ],
        },
        environment: source == 'environment'
            ? const <String, String>{'PRIVATE_SECRET': sentinel}
            : const <String, String>{},
        stdinValue: source == 'stdin' ? sentinel : '',
      );
    }

    final invalidUri = 'otpauth://totp/$sentinel';
    for (final source in <String>['direct', 'environment', 'stdin']) {
      await expectRedactedFailure(
        expectedCode: 'invalid_uri',
        arguments: switch (source) {
          'direct' => <String>[
              'code',
              '--uri',
              invalidUri,
              '--format',
              'json',
            ],
          'environment' => <String>[
              'code',
              '--uri-env',
              'PRIVATE_URI',
              '--format',
              'json',
            ],
          _ => <String>[
              'code',
              '--uri-stdin',
              '--format',
              'json',
            ],
        },
        environment: source == 'environment'
            ? <String, String>{'PRIVATE_URI': invalidUri}
            : const <String, String>{},
        stdinValue: source == 'stdin' ? invalidUri : '',
      );
    }

    await expectRedactedFailure(
      expectedCode: 'conflicting_options',
      arguments: <String>[
        'code',
        '--uri',
        invalidUri,
        '--type',
        'totp',
        '--format',
        'json',
      ],
    );
  });

  test('never leaks direct secret or raw argv values', () async {
    final direct = await failingOutput(<String>[
      'code',
      '--format',
      'json',
      '--secret',
      sentinel,
    ]);
    final argv = await failingOutput(<String>[
      'code',
      '--format',
      'json',
      '--unknown=$sentinel',
    ]);
    expect(direct, isNot(contains(sentinel)));
    expect(argv, isNot(contains(sentinel)));
  });

  test('never leaks URI, environment name/value, or stdin content', () async {
    final uri = await failingOutput(<String>[
      'code',
      '--format',
      'lon',
      '--uri',
      'otpauth://totp/$sentinel?issuer=x',
    ]);
    final env = await failingOutput(<String>[
      'code',
      '--format',
      'json',
      '--secret-env',
      sentinel,
    ], environment: const <String, String>{
      sentinel: sentinel
    });
    final stdin = await failingOutput(<String>[
      'code',
      '--format',
      'json',
      '--secret-stdin',
    ], stdinValue: sentinel);
    expect(uri, isNot(contains(sentinel)));
    expect(env, isNot(contains(sentinel)));
    expect(stdin, isNot(contains(sentinel)));
  });

  test('never leaks unexpected exception text', () async {
    final errors = await failingOutput(<String>[
      'code',
      '--format',
      'json',
      '--secret',
      validSecret,
    ], now: () => throw StateError(sentinel));
    expect(errors, isNot(contains(sentinel)));
    final data = jsonDecode(errors) as Map<String, Object?>;
    final error = data['error']! as Map<String, Object?>;
    expect(error['code'], 'internal_error');
  });
}
