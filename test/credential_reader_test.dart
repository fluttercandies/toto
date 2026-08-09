import 'dart:convert';

import 'package:test/test.dart';
import 'package:toto/src/cli/cli_failure.dart';
import 'package:toto/src/cli/credential_reader.dart';

void main() {
  const secret = 'JBSWY3DPEHPK3PXP';

  CredentialReader reader({
    Map<String, String> environment = const <String, String>{},
    List<List<int>> chunks = const <List<int>>[],
  }) =>
      CredentialReader(
        environment: environment,
        input: Stream<List<int>>.fromIterable(chunks),
      );

  test('reads a direct secret', () async {
    final value = await reader().read(
      const CredentialOptions(secret: secret),
    );
    expect(value.kind, CredentialKind.secret);
    expect(value.value, secret);
  });

  test('reads an environment URI without exposing the variable name', () async {
    const uri = 'otpauth://totp/Acme:alice?secret=$secret';
    final value = await reader(environment: const <String, String>{'OTP': uri})
        .read(const CredentialOptions(uriEnv: 'OTP'));
    expect(value.kind, CredentialKind.uri);
    expect(value.value, uri);
  });

  test('requires exactly one credential source', () async {
    await expectLater(
      reader().read(const CredentialOptions()),
      throwsA(
        isA<CliFailure>()
            .having((error) => error.code, 'code', 'missing_option'),
      ),
    );
    await expectLater(
      reader().read(
        const CredentialOptions(secret: secret, secretEnv: 'OTP'),
      ),
      throwsA(
        isA<CliFailure>()
            .having((error) => error.code, 'code', 'conflicting_options'),
      ),
    );
  });

  test('distinguishes missing and empty environment values safely', () async {
    for (final testCase in <({Map<String, String> env, String code})>[
      (env: const <String, String>{}, code: 'missing_environment'),
      (
        env: const <String, String>{'OTP_SECRET_SENTINEL': ''},
        code: 'empty_environment',
      ),
    ]) {
      try {
        await reader(environment: testCase.env)
            .read(const CredentialOptions(secretEnv: 'OTP_SECRET_SENTINEL'));
        fail('expected failure');
      } on CliFailure catch (error) {
        expect(error.code, testCase.code);
        expect(
            error.toData().toString(), isNot(contains('OTP_SECRET_SENTINEL')));
      }
    }
  });

  test('removes exactly one stdin LF or CRLF', () async {
    for (final source in <String>['$secret\n', '$secret\r\n']) {
      final value = await reader(chunks: <List<int>>[utf8.encode(source)]).read(
        const CredentialOptions(secretStdin: true),
      );
      expect(value.value, secret);
    }

    await expectLater(
      reader(chunks: <List<int>>[utf8.encode('$secret\n\n')]).read(
        const CredentialOptions(secretStdin: true),
      ),
      throwsA(isA<CliFailure>()),
    );
  });

  test('rejects empty and malformed UTF-8 stdin', () async {
    await expectLater(
      reader(chunks: <List<int>>[utf8.encode('\n')]).read(
        const CredentialOptions(secretStdin: true),
      ),
      throwsA(
        isA<CliFailure>().having((error) => error.code, 'code', 'empty_stdin'),
      ),
    );
    await expectLater(
      reader(chunks: const <List<int>>[
        <int>[0xff],
      ]).read(const CredentialOptions(secretStdin: true)),
      throwsA(
        isA<CliFailure>()
            .having((error) => error.code, 'code', 'invalid_arguments'),
      ),
    );
  });

  test('enforces stdin and final secret limits incrementally', () async {
    final oversizedStdin = List<String>.filled(16385, 'A').join();
    await expectLater(
      reader(chunks: <List<int>>[
        utf8.encode(oversizedStdin.substring(0, 9000)),
        utf8.encode(oversizedStdin.substring(9000)),
      ]).read(const CredentialOptions(uriStdin: true)),
      throwsA(
        isA<CliFailure>()
            .having((error) => error.code, 'code', 'input_too_large'),
      ),
    );

    final oversizedSecret = List<String>.filled(4097, 'A').join();
    await expectLater(
      reader().read(CredentialOptions(secret: oversizedSecret)),
      throwsA(
        isA<CliFailure>()
            .having((error) => error.code, 'code', 'input_too_large'),
      ),
    );
  });
}
