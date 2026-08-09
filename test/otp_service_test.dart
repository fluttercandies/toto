import 'package:test/test.dart';
import 'package:toto/src/cli/cli_failure.dart';
import 'package:toto/src/otp/otp_config.dart';
import 'package:toto/src/otp/otp_service.dart';

void main() {
  const hotpSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const sha256Secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
  const sha512Secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
      'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
      'GEZDGNA';
  const service = OtpService();

  group('code generation', () {
    test('matches RFC 4226 counter zero', () {
      final result = service.codeHotp(
        const HotpConfig(secret: hotpSecret, counter: 0),
      );
      expect(result.text, '755224');
      expect(result.data, <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'code',
        'type': 'hotp',
        'code': '755224',
        'algorithm': 'sha1',
        'digits': 6,
        'counter': 0,
      });
    });

    test('matches every RFC 4226 Appendix D vector', () {
      const expected = <String>[
        '755224',
        '287082',
        '359152',
        '969429',
        '338314',
        '254676',
        '287922',
        '162583',
        '399871',
        '520489',
      ];
      for (var counter = 0; counter < expected.length; counter++) {
        final result = service.codeHotp(
          HotpConfig(secret: hotpSecret, counter: counter),
        );
        expect(result.text, expected[counter], reason: 'counter $counter');
      }
    });

    test('matches the RFC 6238 SHA1 vector and validFor formula', () {
      final result = service.codeTotp(
        const TotpConfig(
          secret: hotpSecret,
          digits: 8,
        ),
        DateTime.fromMillisecondsSinceEpoch(59000, isUtc: true),
      );
      expect(result.text, '94287082');
      expect(result.data['validFor'], 1);
      expect(result.data['at'], '1970-01-01T00:00:59Z');
    });

    test('matches every RFC 6238 Appendix B vector', () {
      const vectors = <({
        int seconds,
        String sha1,
        String sha256,
        String sha512,
      })>[
        (seconds: 59, sha1: '94287082', sha256: '46119246', sha512: '90693936'),
        (
          seconds: 1111111109,
          sha1: '07081804',
          sha256: '68084774',
          sha512: '25091201',
        ),
        (
          seconds: 1111111111,
          sha1: '14050471',
          sha256: '67062674',
          sha512: '99943326',
        ),
        (
          seconds: 1234567890,
          sha1: '89005924',
          sha256: '91819424',
          sha512: '93441116',
        ),
        (
          seconds: 2000000000,
          sha1: '69279037',
          sha256: '90698825',
          sha512: '38618901',
        ),
        (
          seconds: 20000000000,
          sha1: '65353130',
          sha256: '77737706',
          sha512: '47863826',
        ),
      ];
      for (final vector in vectors) {
        final at = DateTime.fromMillisecondsSinceEpoch(
          vector.seconds * 1000,
          isUtc: true,
        );
        for (final item in <({
          OtpHash hash,
          String secret,
          String expected,
        })>[
          (hash: OtpHash.sha1, secret: hotpSecret, expected: vector.sha1),
          (
            hash: OtpHash.sha256,
            secret: sha256Secret,
            expected: vector.sha256,
          ),
          (
            hash: OtpHash.sha512,
            secret: sha512Secret,
            expected: vector.sha512,
          ),
        ]) {
          final result = service.codeTotp(
            TotpConfig(
              secret: item.secret,
              digits: 8,
              algorithm: item.hash,
            ),
            at,
          );
          expect(
            result.text,
            item.expected,
            reason: '${vector.seconds}/${item.hash.name}',
          );
        }
      }
    });

    test('supports SHA384 and every allowed digit count', () {
      const expected = <int, String>{
        6: '080675',
        7: '6080675',
        8: '46080675',
      };
      final at = DateTime.fromMillisecondsSinceEpoch(59000, isUtc: true);
      for (final entry in expected.entries) {
        final result = service.codeTotp(
          TotpConfig(
            secret: hotpSecret,
            digits: entry.key,
            algorithm: OtpHash.sha384,
          ),
          at,
        );
        expect(result.text, entry.value, reason: '${entry.key} digits');
        expect(result.data['algorithm'], 'sha384');
      }
    });
  });

  group('verification', () {
    test('finds TOTP offsets in the deterministic window', () {
      const config = TotpConfig(secret: hotpSecret);
      final at = DateTime.utc(2026, 8, 9, 0, 0, 30);
      final previous = service.codeTotp(
        config,
        at.subtract(const Duration(seconds: 30)),
      );
      final checked = service.checkTotp(
        config,
        code: previous.text,
        at: at,
        window: 1,
      );
      expect(checked.exitCode, 0);
      expect(checked.data['valid'], isTrue);
      expect(checked.data['matchedOffset'], -1);
      expect(checked.data['matchedAt'], '2026-08-09T00:00:00Z');
    });

    test('skips negative TOTP steps and can match the next step', () {
      const config = TotpConfig(secret: hotpSecret);
      final epoch = DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);
      final next = service.codeTotp(
        config,
        epoch.add(const Duration(seconds: 30)),
      );
      final checked = service.checkTotp(
        config,
        code: next.text,
        at: epoch,
        window: 1,
      );
      expect(checked.data['matchedOffset'], 1);
    });

    test('skips TOTP window candidates after the maximum supported time', () {
      const config = TotpConfig(secret: hotpSecret, digits: 8);
      final futureCode = service.codeTotp(
        config,
        DateTime.utc(10000, 1, 1, 0, 0, 29),
      );
      final checked = service.checkTotp(
        config,
        code: futureCode.text,
        at: DateTime.utc(9999, 12, 31, 23, 59, 59),
        window: 1,
      );
      expect(checked.exitCode, 1);
      expect(checked.data['valid'], isFalse);
      expect(checked.data['matchedOffset'], isNull);
      expect(checked.data['matchedAt'], isNull);
    });

    test('returns exit 1 and null match fields for a TOTP mismatch', () {
      final checked = service.checkTotp(
        const TotpConfig(secret: hotpSecret),
        code: '000000',
        at: DateTime.utc(2026, 8, 9),
        window: 0,
      );
      expect(checked.exitCode, 1);
      expect(checked.text, 'false');
      expect(checked.data['matchedOffset'], isNull);
      expect(checked.data['matchedAt'], isNull);
    });

    test('returns actual HOTP matched and next counters', () {
      const config = HotpConfig(secret: hotpSecret, counter: 8);
      final code = service.codeHotp(
        const HotpConfig(secret: hotpSecret, counter: 10),
      );
      final checked = service.checkHotp(
        config,
        code: code.text,
        window: 2,
      );
      expect(checked.exitCode, 0);
      expect(checked.data['matchedCounter'], 10);
      expect(checked.data['nextCounter'], 11);
    });

    test('returns null HOTP counters on mismatch', () {
      final checked = service.checkHotp(
        const HotpConfig(secret: hotpSecret, counter: 0),
        code: '000000',
        window: 0,
      );
      expect(checked.exitCode, 1);
      expect(checked.data['matchedCounter'], isNull);
      expect(checked.data['nextCounter'], isNull);
    });

    test('supports the maximum safe match and rejects window overflow', () {
      final config = HotpConfig(
        secret: hotpSecret,
        counter: maxHotpCounter,
      );
      final code = service.codeHotp(config);
      final checked = service.checkHotp(config, code: code.text, window: 0);
      expect(checked.data['nextCounter'], 9223372036854775807);
      expect(
        () => service.checkHotp(config, code: code.text, window: 1),
        throwsA(isA<CliFailure>()),
      );
    });
  });

  group('key and URI generation', () {
    test('generates canonical secure secrets with accurate entropy', () {
      final result = service.createKey(length: 32);
      expect(result.text, matches(r'^[A-Z2-7]{32}$'));
      expect(result.data['command'], 'key');
      expect(result.data['length'], 32);
      expect(result.data['entropyBits'], 160);
      expect(
        () => service.createKey(length: 24),
        throwsA(isA<CliFailure>()),
      );
    });

    test('generates default interoperable TOTP and HOTP URIs', () {
      final totp = service.createTotpUri(
        const TotpConfig(secret: hotpSecret),
        issuer: ' Acme ',
        account: ' alice@example.com ',
      );
      expect(
        totp.text,
        'otpauth://totp/Acme:alice%40example.com?secret=$hotpSecret'
        '&issuer=Acme&digits=6&algorithm=SHA1&period=30',
      );
      expect(totp.data['issuer'], 'Acme');
      expect(totp.data['account'], 'alice@example.com');

      final hotp = service.createHotpUri(
        const HotpConfig(secret: hotpSecret, counter: 7),
        account: 'alice',
      );
      expect(hotp.text, contains('otpauth://hotp/alice?'));
      expect(hotp.text, isNot(contains('issuer=')));
      expect(hotp.text, contains('counter=7'));
      expect(hotp.data['issuer'], isNull);
    });

    test('rejects empty account and explicitly empty issuer', () {
      expect(
        () => service.createTotpUri(
          const TotpConfig(secret: hotpSecret),
          account: '  ',
        ),
        throwsA(isA<CliFailure>()),
      );
      expect(
        () => service.createTotpUri(
          const TotpConfig(secret: hotpSecret),
          issuer: '  ',
          account: 'alice',
        ),
        throwsA(isA<CliFailure>()),
      );
    });
  });
}
