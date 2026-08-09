import 'package:dart_dash_otp/dart_dash_otp.dart';

import '../cli/cli_failure.dart';
import 'otp_config.dart';

final class CommandResult {
  const CommandResult({
    required this.text,
    required this.data,
    this.exitCode = 0,
  });

  final String text;
  final Map<String, Object?> data;
  final int exitCode;
}

final class OtpService {
  const OtpService();

  CommandResult codeTotp(TotpConfig config, DateTime at) {
    final token = _totp(config);
    final code = token.value(date: at)!;
    final unixSeconds = at.millisecondsSinceEpoch ~/ 1000;
    return CommandResult(
      text: code,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'code',
        'type': 'totp',
        'code': code,
        'algorithm': config.algorithm.name,
        'digits': config.digits,
        'period': config.period,
        'at': formatUtcSeconds(at),
        'validFor': config.period - (unixSeconds % config.period),
      },
    );
  }

  CommandResult codeHotp(HotpConfig config) {
    final code = _hotp(config).at(counter: config.counter)!;
    return CommandResult(
      text: code,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'code',
        'type': 'hotp',
        'code': code,
        'algorithm': config.algorithm.name,
        'digits': config.digits,
        'counter': config.counter,
      },
    );
  }

  CommandResult checkTotp(
    TotpConfig config, {
    required String code,
    required DateTime at,
    required int window,
  }) {
    validateOtpCode(code, digits: config.digits);
    final token = _totp(config);
    final referenceSeconds = at.millisecondsSinceEpoch ~/ 1000;
    int? matchedOffset;
    DateTime? matchedAt;
    for (final offset in totpWindowOffsets(window)) {
      final candidateSeconds = referenceSeconds + offset * config.period;
      if (candidateSeconds < 0 || candidateSeconds > maxUnixSeconds) {
        continue;
      }
      final candidate = DateTime.fromMillisecondsSinceEpoch(
        candidateSeconds * 1000,
        isUtc: true,
      );
      if (token.verify(otp: code, time: candidate, window: 0)) {
        matchedOffset = offset;
        matchedAt = candidate;
        break;
      }
    }
    final valid = matchedOffset != null;
    return CommandResult(
      text: valid.toString(),
      exitCode: valid ? 0 : 1,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'check',
        'type': 'totp',
        'valid': valid,
        'algorithm': config.algorithm.name,
        'digits': config.digits,
        'period': config.period,
        'at': formatUtcSeconds(at),
        'window': window,
        'matchedOffset': matchedOffset,
        'matchedAt': matchedAt == null ? null : formatUtcSeconds(matchedAt),
      },
    );
  }

  CommandResult checkHotp(
    HotpConfig config, {
    required String code,
    required int window,
  }) {
    validateOtpCode(code, digits: config.digits);
    validateCounterWindow(config.counter, window);
    final token = _hotp(config);
    int? matchedCounter;
    for (var offset = 0; offset <= window; offset++) {
      final candidate = config.counter + offset;
      if (token.verify(otp: code, counter: candidate, window: 0)) {
        matchedCounter = candidate;
        break;
      }
    }
    final valid = matchedCounter != null;
    return CommandResult(
      text: valid.toString(),
      exitCode: valid ? 0 : 1,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'check',
        'type': 'hotp',
        'valid': valid,
        'algorithm': config.algorithm.name,
        'digits': config.digits,
        'counter': config.counter,
        'window': window,
        'matchedCounter': matchedCounter,
        'nextCounter': matchedCounter == null ? null : matchedCounter + 1,
      },
    );
  }

  CommandResult createKey({required int length}) {
    if (length < 32 || length > 1024 || length % 8 != 0) {
      throw const CliFailure(
        code: 'invalid_option',
        message: 'Invalid option.',
        details: <String, Object?>{
          'option': 'length',
          'expected': 'integer:32..1024 multiple-of:8',
        },
      );
    }
    final secret = OTP.randomSecret(length: length);
    return CommandResult(
      text: secret,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'key',
        'secret': secret,
        'length': length,
        'entropyBits': length * 5,
      },
    );
  }

  CommandResult createTotpUri(
    TotpConfig config, {
    String? issuer,
    required String account,
  }) {
    final labels = _labels(issuer: issuer, account: account);
    final uri = _withoutEmptyIssuer(
      _totp(config).generateUrl(
        issuer: labels.issuer,
        account: labels.account,
      ),
      issuer: labels.issuer,
    );
    return CommandResult(
      text: uri,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'uri',
        'type': 'totp',
        'uri': uri,
        'algorithm': config.algorithm.name,
        'digits': config.digits,
        'issuer': labels.issuer,
        'account': labels.account,
        'period': config.period,
      },
    );
  }

  CommandResult createHotpUri(
    HotpConfig config, {
    String? issuer,
    required String account,
  }) {
    final labels = _labels(issuer: issuer, account: account);
    final uri = _withoutEmptyIssuer(
      _hotp(config).generateUrl(
        issuer: labels.issuer,
        account: labels.account,
      ),
      issuer: labels.issuer,
    );
    return CommandResult(
      text: uri,
      data: <String, Object?>{
        'schemaVersion': 1,
        'status': 'ok',
        'command': 'uri',
        'type': 'hotp',
        'uri': uri,
        'algorithm': config.algorithm.name,
        'digits': config.digits,
        'issuer': labels.issuer,
        'account': labels.account,
        'counter': config.counter,
      },
    );
  }

  TOTP _totp(TotpConfig config) => TOTP(
        secret: config.secret,
        digits: config.digits,
        interval: config.period,
        algorithm: config.algorithm.dependencyValue,
      );

  HOTP _hotp(HotpConfig config) => HOTP(
        secret: config.secret,
        digits: config.digits,
        counter: config.counter,
        algorithm: config.algorithm.dependencyValue,
      );

  String _withoutEmptyIssuer(String source, {required String? issuer}) {
    if (issuer != null) {
      return source;
    }
    final uri = Uri.parse(source);
    return uri.replace(
      queryParameters: <String, String>{
        for (final entry in uri.queryParameters.entries)
          if (entry.key != 'issuer') entry.key: entry.value,
      },
    ).toString();
  }

  ({String? issuer, String account}) _labels({
    required String? issuer,
    required String account,
  }) {
    final normalizedAccount = account.trim();
    if (normalizedAccount.isEmpty) {
      throw const CliFailure(
        code: 'invalid_option',
        message: 'Invalid option.',
        details: <String, Object?>{
          'option': 'account',
          'expected': 'non-empty',
        },
      );
    }
    final normalizedIssuer = issuer?.trim();
    if (issuer != null && normalizedIssuer!.isEmpty) {
      throw const CliFailure(
        code: 'invalid_option',
        message: 'Invalid option.',
        details: <String, Object?>{
          'option': 'issuer',
          'expected': 'non-empty',
        },
      );
    }
    return (issuer: normalizedIssuer, account: normalizedAccount);
  }
}
