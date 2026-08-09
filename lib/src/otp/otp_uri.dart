import 'package:dart_dash_otp/dart_dash_otp.dart';

import '../cli/cli_failure.dart';
import 'otp_config.dart';

final class ParsedOtpUri {
  const ParsedOtpUri({
    required this.kind,
    required this.secret,
    required this.digits,
    required this.algorithm,
    this.period,
    this.counter,
  });

  final OtpKind kind;
  final String secret;
  final int digits;
  final OtpHash algorithm;
  final int? period;
  final int? counter;
}

ParsedOtpUri parseOtpAuthUri(String source) {
  if (source.length > 16384) {
    throw const CliFailure(
      code: 'input_too_large',
      message: 'Input is too large.',
      details: <String, Object?>{
        'source': 'uri',
        'maxCodeUnits': 16384,
      },
    );
  }
  final uri = Uri.tryParse(source);
  if (uri == null || uri.scheme != 'otpauth') {
    throw _invalidUri('scheme');
  }
  final kind = switch (uri.host) {
    'totp' => OtpKind.totp,
    'hotp' => OtpKind.hotp,
    _ => throw _invalidUri('type'),
  };
  final authority = _rawAuthority(source);
  if (authority.contains('@') || authority.contains(':') || uri.hasPort) {
    throw _invalidUri('authority');
  }
  if (uri.hasFragment) {
    throw _invalidUri('fragment');
  }
  final hasLabel = uri.pathSegments.any(
    (segment) => segment.trim().isNotEmpty,
  );
  if (!hasLabel) {
    throw _invalidUri('label');
  }

  final allowed = kind == OtpKind.totp
      ? const <String>{'secret', 'issuer', 'digits', 'algorithm', 'period'}
      : const <String>{'secret', 'issuer', 'digits', 'algorithm', 'counter'};
  final parameters = uri.queryParametersAll;
  for (final entry in parameters.entries) {
    if (!allowed.contains(entry.key)) {
      throw _invalidUri('unknown_query');
    }
    if (entry.value.length != 1) {
      throw _invalidUri('duplicate_query');
    }
  }

  final secretValue = _single(parameters, 'secret');
  if (secretValue == null || secretValue.isEmpty) {
    throw _invalidUri('missing_secret');
  }
  final secret = validateSecret(secretValue);
  final digits = _parseUriInt(
    _single(parameters, 'digits'),
    name: 'digits',
    min: 6,
    max: 8,
    defaultValue: 6,
  );
  final algorithm = _parseUriAlgorithm(_single(parameters, 'algorithm'));

  if (kind == OtpKind.totp) {
    final period = _parseUriInt(
      _single(parameters, 'period'),
      name: 'period',
      min: 1,
      max: 86400,
      defaultValue: 30,
    );
    try {
      TOTP.fromUri(source);
    } on Object {
      throw _invalidUri('dependency');
    }
    return ParsedOtpUri(
      kind: kind,
      secret: secret,
      digits: digits,
      algorithm: algorithm,
      period: period,
    );
  }

  final counterValue = _single(parameters, 'counter');
  if (counterValue == null || counterValue.isEmpty) {
    throw _invalidUri('missing_counter');
  }
  final counter = _parseUriInt(
    counterValue,
    name: 'counter',
    min: 0,
    max: maxHotpCounter,
  );
  try {
    HOTP.fromUri(source);
  } on Object {
    throw _invalidUri('dependency');
  }
  return ParsedOtpUri(
    kind: kind,
    secret: secret,
    digits: digits,
    algorithm: algorithm,
    counter: counter,
  );
}

String _rawAuthority(String source) {
  const prefix = 'otpauth://';
  final start = prefix.length;
  var end = source.length;
  for (final delimiter in const <String>['/', '?', '#']) {
    final index = source.indexOf(delimiter, start);
    if (index != -1 && index < end) {
      end = index;
    }
  }
  return source.substring(start, end);
}

void validateOtpOptionCompatibility({
  required OtpKind kind,
  required bool uriInput,
  required Set<String> provided,
}) {
  final conflicts = <String>{};
  if (uriInput) {
    conflicts.addAll(_uriOwnedConflicts(provided));
  }
  if (kind == OtpKind.totp && provided.contains('counter')) {
    conflicts.add('counter');
  }
  if (kind == OtpKind.hotp) {
    conflicts.addAll(provided.intersection(const <String>{'period', 'at'}));
  }
  _throwOptionConflicts(conflicts);
}

void validateUriOwnedOptions(Set<String> provided) {
  _throwOptionConflicts(_uriOwnedConflicts(provided));
}

Set<String> _uriOwnedConflicts(Set<String> provided) => provided.intersection(
      const <String>{'type', 'digits', 'algorithm', 'period'},
    );

void _throwOptionConflicts(Set<String> conflicts) {
  if (conflicts.isEmpty) {
    return;
  }
  throw CliFailure(
    code: 'conflicting_options',
    message: 'Conflicting options.',
    details: <String, Object?>{
      'options': conflicts.toList()..sort(),
    },
  );
}

String? _single(Map<String, List<String>> parameters, String key) {
  final values = parameters[key];
  return values?.single;
}

int _parseUriInt(
  String? value, {
  required String name,
  required int min,
  required int max,
  int? defaultValue,
}) {
  if (value == null) {
    if (defaultValue != null) {
      return defaultValue;
    }
    throw _invalidUri(name);
  }
  if (!RegExp(r'^[0-9]+$').hasMatch(value)) {
    throw _invalidUri(name);
  }
  final parsed = int.tryParse(value);
  if (parsed == null || parsed < min || parsed > max) {
    throw _invalidUri(name);
  }
  return parsed;
}

OtpHash _parseUriAlgorithm(String? value) => switch (value?.toUpperCase()) {
      null || 'SHA1' => OtpHash.sha1,
      'SHA256' => OtpHash.sha256,
      'SHA384' => OtpHash.sha384,
      'SHA512' => OtpHash.sha512,
      _ => throw _invalidUri('algorithm'),
    };

CliFailure _invalidUri(String reason) => CliFailure(
      code: 'invalid_uri',
      message: 'Invalid OTP URI.',
      details: <String, Object?>{'reason': reason},
    );
