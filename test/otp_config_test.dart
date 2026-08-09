import 'package:test/test.dart';
import 'package:toto/src/cli/cli_failure.dart';
import 'package:toto/src/otp/otp_config.dart';

void main() {
  group('enum parsing', () {
    test('uses totp as the absent CLI type and accepts exact lower-case names',
        () {
      expect(OtpKind.parseCli(null), OtpKind.totp);
      expect(OtpKind.parseCli('totp'), OtpKind.totp);
      expect(OtpKind.parseCli('hotp'), OtpKind.hotp);
      expect(() => OtpKind.parseCli('TOTP'), throwsA(isA<CliFailure>()));
      expect(OtpKind.totp.name, 'totp');
    });

    test('accepts exact lower-case CLI algorithms', () {
      expect(OtpHash.parseCli(null), OtpHash.sha1);
      expect(OtpHash.parseCli('sha256'), OtpHash.sha256);
      expect(OtpHash.parseCli('sha384'), OtpHash.sha384);
      expect(OtpHash.parseCli('sha512'), OtpHash.sha512);
      expect(() => OtpHash.parseCli('SHA1'), throwsA(isA<CliFailure>()));
      expect(OtpHash.sha512.name, 'sha512');
    });
  });

  group('numeric bounds', () {
    test('parses the accepted edge values', () {
      expect(parseBoundedInt('6', option: 'digits', min: 6, max: 8), 6);
      expect(parseBoundedInt('8', option: 'digits', min: 6, max: 8), 8);
      expect(parseBoundedInt('0', option: 'window', min: 0, max: 10), 0);
      expect(
        parseBoundedInt(
          '9223372036854775806',
          option: 'counter',
          min: 0,
          max: maxHotpCounter,
        ),
        maxHotpCounter,
      );
    });

    test('rejects signs, whitespace, decimals, overflow, and out of range', () {
      for (final value in <String>['+6', ' 6', '6.0', 'x', '9']) {
        expect(
          () => parseBoundedInt(value, option: 'digits', min: 6, max: 8),
          throwsA(isA<CliFailure>()),
          reason: value,
        );
      }
    });

    test('rejects counter windows that cannot produce a safe next counter', () {
      expect(
        () => validateCounterWindow(maxHotpCounter - 1, 1),
        returnsNormally,
      );
      expect(
        () => validateCounterWindow(maxHotpCounter, 1),
        throwsA(isA<CliFailure>()),
      );
    });
  });

  group('secret validation', () {
    test('accepts canonical uppercase unpadded Base32', () {
      expect(
        validateSecret('JBSWY3DPEHPK3PXP'),
        'JBSWY3DPEHPK3PXP',
      );
      expect(validateSecret('MY'), 'MY');
    });

    test('rejects lowercase, padding, whitespace, invalid residues and short',
        () {
      for (final value in <String>[
        'jbswy3dpehpk3pxp',
        'JBSWY3DP=',
        'JBSW Y3DP',
        'J',
        'ABC',
        'MZ',
      ]) {
        expect(
          () => validateSecret(value),
          throwsA(isA<CliFailure>()),
          reason: value,
        );
      }
    });

    test('rejects a secret over 4096 code units without exposing it', () {
      final sentinel = List<String>.filled(4097, 'A').join();
      try {
        validateSecret(sentinel);
        fail('expected failure');
      } on CliFailure catch (error) {
        expect(error.code, 'input_too_large');
        expect(error.toData().toString(), isNot(contains(sentinel)));
      }
    });
  });

  group('time parsing and formatting', () {
    final fallback = DateTime.utc(2026, 8, 9, 12, 34, 56, 789, 123);

    test('uses injected now and truncates to UTC seconds', () {
      final value = parseOtpTime(null, now: () => fallback);
      expect(value, DateTime.utc(2026, 8, 9, 12, 34, 56));
      expect(formatUtcSeconds(value), '2026-08-09T12:34:56Z');
    });

    test('accepts bounded Unix seconds and timezone-qualified RFC 3339', () {
      expect(
        parseOtpTime('0', now: () => fallback),
        DateTime.utc(1970),
      );
      expect(
        parseOtpTime('2026-08-09T20:34:56+08:00', now: () => fallback),
        DateTime.utc(2026, 8, 9, 12, 34, 56),
      );
      expect(
        parseOtpTime(
          '2026-08-09T12:34:56.123456789Z',
          now: () => fallback,
        ),
        DateTime.utc(2026, 8, 9, 12, 34, 56),
      );
      expect(
        formatUtcSeconds(
          parseOtpTime('253402300799', now: () => fallback),
        ),
        '9999-12-31T23:59:59Z',
      );
    });

    test('rejects negative, excessive, timezone-free, and normalized dates',
        () {
      for (final value in <String>[
        '-1',
        '253402300800',
        '1970-01-01T00:00:59.999+00:01',
        '2026-08-09T12:34:56',
        '2026-02-30T12:34:56Z',
        '2026-08-09',
      ]) {
        expect(
          () => parseOtpTime(value, now: () => fallback),
          throwsA(isA<CliFailure>()),
          reason: value,
        );
      }
    });
  });

  group('code and window validation', () {
    test('accepts only exact-length ASCII digits', () {
      expect(validateOtpCode('012345', digits: 6), '012345');
      for (final value in <String>['12345', '1234567', '１２３４５６', '12a456']) {
        expect(
          () => validateOtpCode(value, digits: 6),
          throwsA(isA<CliFailure>()),
          reason: value,
        );
      }
    });

    test('returns deterministic closest-first TOTP offsets', () {
      expect(totpWindowOffsets(0), <int>[0]);
      expect(totpWindowOffsets(3), <int>[0, -1, 1, -2, 2, -3, 3]);
    });
  });
}
