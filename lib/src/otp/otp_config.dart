import 'package:dart_dash_otp/dart_dash_otp.dart';

import '../cli/cli_failure.dart';

const maxHotpCounter = 9223372036854775806;
const maxUnixSeconds = 253402300799;

enum OtpKind {
  totp,
  hotp;

  static OtpKind parseCli(String? value) => switch (value) {
        null || 'totp' => OtpKind.totp,
        'hotp' => OtpKind.hotp,
        _ => throw _invalidOption('type', 'enum:totp|hotp'),
      };
}

enum OtpHash {
  sha1,
  sha256,
  sha384,
  sha512;

  static OtpHash parseCli(String? value) => switch (value) {
        null || 'sha1' => OtpHash.sha1,
        'sha256' => OtpHash.sha256,
        'sha384' => OtpHash.sha384,
        'sha512' => OtpHash.sha512,
        _ => throw _invalidOption(
            'algorithm',
            'enum:sha1|sha256|sha384|sha512',
          ),
      };

  OTPAlgorithm get dependencyValue => switch (this) {
        OtpHash.sha1 => OTPAlgorithm.SHA1,
        OtpHash.sha256 => OTPAlgorithm.SHA256,
        OtpHash.sha384 => OTPAlgorithm.SHA384,
        OtpHash.sha512 => OTPAlgorithm.SHA512,
      };
}

final class TotpConfig {
  const TotpConfig({
    required this.secret,
    this.digits = 6,
    this.algorithm = OtpHash.sha1,
    this.period = 30,
  });

  final String secret;
  final int digits;
  final OtpHash algorithm;
  final int period;
}

final class HotpConfig {
  const HotpConfig({
    required this.secret,
    required this.counter,
    this.digits = 6,
    this.algorithm = OtpHash.sha1,
  });

  final String secret;
  final int counter;
  final int digits;
  final OtpHash algorithm;
}

int parseBoundedInt(
  String value, {
  required String option,
  required int min,
  required int max,
}) {
  if (!RegExp(r'^[0-9]+$').hasMatch(value)) {
    throw _invalidOption(option, 'integer:$min..$max');
  }
  final parsed = int.tryParse(value);
  if (parsed == null || parsed < min || parsed > max) {
    throw _invalidOption(option, 'integer:$min..$max');
  }
  return parsed;
}

void validateCounterWindow(int counter, int window) {
  if (counter < 0 ||
      counter > maxHotpCounter ||
      window < 0 ||
      window > 10 ||
      counter > maxHotpCounter - window) {
    throw _invalidOption(
      'counter',
      'integer:0..$maxHotpCounter with counter+window in range',
    );
  }
}

String validateSecret(String value) {
  if (value.length > 4096) {
    throw const CliFailure(
      code: 'input_too_large',
      message: 'Input is too large.',
      details: <String, Object?>{
        'source': 'secret',
        'maxCodeUnits': 4096,
      },
    );
  }
  final residue = value.length % 8;
  final validResidue = residue == 0 ||
      residue == 2 ||
      residue == 4 ||
      residue == 5 ||
      residue == 7;
  if (value.isEmpty ||
      !validResidue ||
      !RegExp(r'^[A-Z2-7]+$').hasMatch(value) ||
      !_hasCanonicalBase32PadBits(value, residue)) {
    throw const CliFailure(
      code: 'invalid_secret',
      message: 'Invalid OTP secret.',
      details: <String, Object?>{'reason': 'format'},
    );
  }
  try {
    TOTP(secret: value);
  } on ArgumentError {
    throw const CliFailure(
      code: 'invalid_secret',
      message: 'Invalid OTP secret.',
      details: <String, Object?>{'reason': 'too_short'},
    );
  }
  return value;
}

bool _hasCanonicalBase32PadBits(String value, int residue) {
  final unusedBits = switch (residue) {
    2 => 2,
    4 => 4,
    5 => 1,
    7 => 3,
    _ => 0,
  };
  if (unusedBits == 0) {
    return true;
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  final lastValue = alphabet.indexOf(value[value.length - 1]);
  final unusedMask = (1 << unusedBits) - 1;
  return lastValue & unusedMask == 0;
}

DateTime parseOtpTime(
  String? value, {
  required DateTime Function() now,
}) {
  if (value == null) {
    return _validateAndTruncateTime(now().toUtc());
  }
  if (RegExp(r'^[0-9]+$').hasMatch(value)) {
    final seconds = int.tryParse(value);
    if (seconds == null || seconds > maxUnixSeconds) {
      throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
    }
    return DateTime.fromMillisecondsSinceEpoch(
      seconds * 1000,
      isUtc: true,
    );
  }

  final match = RegExp(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})'
    r'(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$',
  ).firstMatch(value);
  if (match == null) {
    throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
  }

  final year = int.parse(match.group(1)!);
  final month = int.parse(match.group(2)!);
  final day = int.parse(match.group(3)!);
  final hour = int.parse(match.group(4)!);
  final minute = int.parse(match.group(5)!);
  final second = int.parse(match.group(6)!);
  final fractionDigits = match.group(7) ?? '';
  final fraction = (fractionDigits.length > 6
          ? fractionDigits.substring(0, 6)
          : fractionDigits)
      .padRight(6, '0');
  final microsecond = fraction.isEmpty ? 0 : int.parse(fraction);
  final zone = match.group(8)!;

  if (month < 1 ||
      month > 12 ||
      day < 1 ||
      day > 31 ||
      hour > 23 ||
      minute > 59 ||
      second > 59) {
    throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
  }

  final local = DateTime.utc(
    year,
    month,
    day,
    hour,
    minute,
    second,
    microsecond ~/ 1000,
    microsecond % 1000,
  );
  if (local.year != year ||
      local.month != month ||
      local.day != day ||
      local.hour != hour ||
      local.minute != minute ||
      local.second != second) {
    throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
  }

  var offsetMinutes = 0;
  if (zone != 'Z') {
    final offsetHour = int.parse(zone.substring(1, 3));
    final offsetMinute = int.parse(zone.substring(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) {
      throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
    }
    offsetMinutes = offsetHour * 60 + offsetMinute;
    if (zone.startsWith('-')) {
      offsetMinutes = -offsetMinutes;
    }
  }
  return _validateAndTruncateTime(
    local.subtract(Duration(minutes: offsetMinutes)),
  );
}

DateTime _validateAndTruncateTime(DateTime value) {
  final microseconds = value.microsecondsSinceEpoch;
  if (microseconds < 0) {
    throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
  }
  final seconds = microseconds ~/ Duration.microsecondsPerSecond;
  if (seconds > maxUnixSeconds) {
    throw _invalidOption('at', 'unix:0..$maxUnixSeconds or RFC3339');
  }
  return DateTime.fromMillisecondsSinceEpoch(
    seconds * 1000,
    isUtc: true,
  );
}

String formatUtcSeconds(DateTime value) {
  final utc = value.toUtc();
  String two(int part) => part.toString().padLeft(2, '0');
  return '${utc.year.toString().padLeft(4, '0')}-'
      '${two(utc.month)}-${two(utc.day)}T${two(utc.hour)}:'
      '${two(utc.minute)}:${two(utc.second)}Z';
}

String validateOtpCode(String value, {required int digits}) {
  if (!RegExp('^[0-9]{$digits}\$').hasMatch(value)) {
    throw _invalidOption('code', 'digits:$digits');
  }
  return value;
}

List<int> totpWindowOffsets(int window) {
  if (window < 0 || window > 10) {
    throw _invalidOption('window', 'integer:0..10');
  }
  return <int>[
    0,
    for (var distance = 1; distance <= window; distance++) ...<int>[
      -distance,
      distance,
    ],
  ];
}

CliFailure _invalidOption(String option, String expected) => CliFailure(
      code: 'invalid_option',
      message: 'Invalid option.',
      details: <String, Object?>{
        'option': option,
        'expected': expected,
      },
    );
