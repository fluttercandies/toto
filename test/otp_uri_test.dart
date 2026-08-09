import 'package:test/test.dart';
import 'package:toto/src/cli/cli_failure.dart';
import 'package:toto/src/otp/otp_config.dart';
import 'package:toto/src/otp/otp_uri.dart';

void main() {
  const secret = 'JBSWY3DPEHPK3PXP';

  group('strict URI parsing', () {
    test('applies TOTP defaults and normalizes URI algorithm case', () {
      final token = parseOtpAuthUri(
        'otpauth://totp/Acme:alice?secret=$secret&algorithm=Sha256',
      );
      expect(token.kind, OtpKind.totp);
      expect(token.secret, secret);
      expect(token.digits, 6);
      expect(token.algorithm, OtpHash.sha256);
      expect(token.period, 30);
      expect(token.counter, isNull);
    });

    test('requires secret and HOTP counter before dependency parsing', () {
      for (final uri in <String>[
        'otpauth://totp/Acme:alice?period=30',
        'otpauth://hotp/Acme:alice?secret=$secret',
      ]) {
        expect(
          () => parseOtpAuthUri(uri),
          throwsA(
            isA<CliFailure>()
                .having((error) => error.code, 'code', 'invalid_uri'),
          ),
          reason: uri,
        );
      }
    });

    test('accepts a complete HOTP URI', () {
      final token = parseOtpAuthUri(
        'otpauth://hotp/Acme:alice?secret=$secret&counter=42&digits=8',
      );
      expect(token.kind, OtpKind.hotp);
      expect(token.counter, 42);
      expect(token.digits, 8);
      expect(token.period, isNull);
    });

    test('rejects invalid authority, label, fragment, and unknown query', () {
      for (final uri in <String>[
        'https://totp/Acme:alice?secret=$secret',
        'otpauth://unknown/Acme:alice?secret=$secret',
        'otpauth://user@totp/Acme:alice?secret=$secret',
        'otpauth://@totp/Acme:alice?secret=$secret',
        'otpauth://totp:123/Acme:alice?secret=$secret',
        'otpauth://totp/?secret=$secret',
        'otpauth://totp//?secret=$secret',
        'otpauth://totp/Acme:alice?secret=$secret#fragment',
        'otpauth://totp/Acme:alice?secret=$secret#',
        'otpauth://totp/Acme:alice?secret=$secret&peroid=30',
      ]) {
        expect(
          () => parseOtpAuthUri(uri),
          throwsA(isA<CliFailure>()),
          reason: uri,
        );
      }
    });

    test('rejects duplicate and explicitly invalid query values', () {
      for (final uri in <String>[
        'otpauth://totp/A?secret=$secret&secret=$secret',
        'otpauth://totp/A?secret=$secret&digits=x',
        'otpauth://totp/A?secret=$secret&period=0',
        'otpauth://totp/A?secret=$secret&algorithm=md5',
        'otpauth://totp/A?secret=$secret&counter=0',
        'otpauth://hotp/A?secret=$secret&counter=x',
        'otpauth://hotp/A?secret=$secret&counter=0&period=30',
      ]) {
        expect(
          () => parseOtpAuthUri(uri),
          throwsA(isA<CliFailure>()),
          reason: uri,
        );
      }
    });
  });

  group('CLI option compatibility', () {
    test('URI owns type, digits, algorithm, and period', () {
      for (final option in <String>['type', 'digits', 'algorithm', 'period']) {
        expect(
          () => validateOtpOptionCompatibility(
            kind: OtpKind.totp,
            uriInput: true,
            provided: <String>{option},
          ),
          throwsA(
            isA<CliFailure>()
                .having((error) => error.code, 'code', 'conflicting_options'),
          ),
          reason: option,
        );
      }
    });

    test('rejects options that do not apply to the final type', () {
      expect(
        () => validateOtpOptionCompatibility(
          kind: OtpKind.totp,
          uriInput: false,
          provided: const <String>{'counter'},
        ),
        throwsA(isA<CliFailure>()),
      );
      for (final option in <String>['period', 'at']) {
        expect(
          () => validateOtpOptionCompatibility(
            kind: OtpKind.hotp,
            uriInput: false,
            provided: <String>{option},
          ),
          throwsA(isA<CliFailure>()),
          reason: option,
        );
      }
    });

    test('allows HOTP URI counter override', () {
      expect(
        () => validateOtpOptionCompatibility(
          kind: OtpKind.hotp,
          uriInput: true,
          provided: const <String>{'counter'},
        ),
        returnsNormally,
      );
    });
  });
}
