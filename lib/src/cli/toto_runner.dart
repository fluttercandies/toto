import 'package:args/args.dart';

import '../otp/otp_config.dart';
import '../otp/otp_service.dart';
import '../otp/otp_uri.dart';
import '../output/output_encoder.dart';
import '../version.dart';
import 'cli_failure.dart';
import 'credential_reader.dart';

final class TotoRunner {
  const TotoRunner({
    required this.input,
    required this.output,
    required this.errorOutput,
    required this.environment,
    required this.now,
    this.service = const OtpService(),
    this.encoder = const OutputEncoder(),
  });

  final Stream<List<int>> input;
  final StringSink output;
  final StringSink errorOutput;
  final Map<String, String> environment;
  final DateTime Function() now;
  final OtpService service;
  final OutputEncoder encoder;

  Future<int> run(List<String> arguments) async {
    final formatScan = _FormatScan.scan(arguments);
    final format = formatScan.format;
    try {
      if (formatScan.invalid ||
          _hasRepeatedSingleValueOption(formatScan.arguments)) {
        throw const CliFailure(
          code: 'invalid_arguments',
          message: 'Invalid arguments.',
        );
      }
      final parser = _buildParser();
      final ArgResults root;
      try {
        root = parser.parse(formatScan.arguments);
      } on ArgParserException {
        throw const CliFailure(
          code: 'invalid_arguments',
          message: 'Invalid arguments.',
        );
      }

      if (root.flag('version')) {
        output.write('toto $totoVersion\n');
        return 0;
      }
      if (root.flag('help')) {
        output.write(_rootHelp(parser));
        return 0;
      }

      final command = root.command;
      if (command == null) {
        throw const CliFailure(
          code: 'unknown_command',
          message: 'Unknown command.',
        );
      }
      final canonical = _canonicalCommand(command.name!);
      if (command.flag('help')) {
        output.write(_commandHelp(canonical));
        return 0;
      }

      final result = switch (canonical) {
        'code' => await _runOtp(command, check: false),
        'check' => await _runOtp(command, check: true),
        'key' => _runKey(command),
        'uri' => await _runUri(command),
        _ => throw const CliFailure(
            code: 'unknown_command',
            message: 'Unknown command.',
          ),
      };
      output.write(
        encoder.success(
          format: format,
          text: result.text,
          data: result.data,
        ),
      );
      return result.exitCode;
    } on CliFailure catch (failure) {
      errorOutput.write(encoder.failure(format: format, failure: failure));
      return failure.exitCode;
    } on Object {
      const failure = CliFailure(
        code: 'internal_error',
        message: 'Internal error.',
        exitCode: 70,
      );
      errorOutput.write(encoder.failure(format: format, failure: failure));
      return failure.exitCode;
    }
  }

  Future<CommandResult> _runOtp(
    ArgResults arguments, {
    required bool check,
  }) async {
    if (check) {
      if (arguments.rest.isEmpty) {
        throw const CliFailure(
          code: 'missing_argument',
          message: 'Missing required argument.',
          details: <String, Object?>{'argument': 'code'},
        );
      }
      if (arguments.rest.length != 1) {
        throw const CliFailure(
          code: 'invalid_arguments',
          message: 'Invalid arguments.',
        );
      }
    } else if (arguments.rest.isNotEmpty) {
      throw const CliFailure(
        code: 'invalid_arguments',
        message: 'Invalid arguments.',
      );
    }

    final credentialOptions = _credentialOptions(arguments, allowUri: true);
    final provided = _providedOtpOptions(arguments);
    if (credentialOptions.selectedSourceCount == 1 &&
        credentialOptions.hasUriSource) {
      validateUriOwnedOptions(provided);
    } else if (credentialOptions.selectedSourceCount == 1 &&
        credentialOptions.hasSecretSource) {
      _validateRawOtpOptionsBeforeRead(arguments, provided);
    }
    final credential = await CredentialReader(
      environment: environment,
      input: input,
    ).read(credentialOptions);

    late final OtpKind kind;
    late final String secret;
    late final int digits;
    late final OtpHash algorithm;
    int? period;
    int? counter;

    if (credential.kind == CredentialKind.uri) {
      final uri = parseOtpAuthUri(credential.value);
      kind = uri.kind;
      secret = uri.secret;
      digits = uri.digits;
      algorithm = uri.algorithm;
      period = uri.period;
      counter = uri.counter;
      validateOtpOptionCompatibility(
        kind: kind,
        uriInput: true,
        provided: provided,
      );
      if (kind == OtpKind.hotp && arguments.wasParsed('counter')) {
        counter = _boundedOption(
          arguments,
          'counter',
          min: 0,
          max: maxHotpCounter,
        );
      }
    } else {
      kind = OtpKind.parseCli(arguments.option('type'));
      secret = credential.value;
      digits = _boundedOption(
        arguments,
        'digits',
        min: 6,
        max: 8,
        defaultValue: 6,
      );
      algorithm = OtpHash.parseCli(arguments.option('algorithm'));
      validateOtpOptionCompatibility(
        kind: kind,
        uriInput: false,
        provided: provided,
      );
      if (kind == OtpKind.totp) {
        period = _boundedOption(
          arguments,
          'period',
          min: 1,
          max: 86400,
          defaultValue: 30,
        );
      } else {
        if (!arguments.wasParsed('counter')) {
          throw const CliFailure(
            code: 'missing_option',
            message: 'Missing required option.',
            details: <String, Object?>{'option': 'counter'},
          );
        }
        counter = _boundedOption(
          arguments,
          'counter',
          min: 0,
          max: maxHotpCounter,
        );
      }
    }

    if (kind == OtpKind.totp) {
      final config = TotpConfig(
        secret: secret,
        digits: digits,
        algorithm: algorithm,
        period: period!,
      );
      final at = parseOtpTime(arguments.option('at'), now: now);
      if (!check) {
        return service.codeTotp(config, at);
      }
      final window = _boundedOption(
        arguments,
        'window',
        min: 0,
        max: 10,
        defaultValue: 0,
      );
      return service.checkTotp(
        config,
        code: arguments.rest.single,
        at: at,
        window: window,
      );
    }

    final config = HotpConfig(
      secret: secret,
      digits: digits,
      algorithm: algorithm,
      counter: counter!,
    );
    if (!check) {
      return service.codeHotp(config);
    }
    final window = _boundedOption(
      arguments,
      'window',
      min: 0,
      max: 10,
      defaultValue: 0,
    );
    return service.checkHotp(
      config,
      code: arguments.rest.single,
      window: window,
    );
  }

  CommandResult _runKey(ArgResults arguments) {
    if (arguments.rest.isNotEmpty) {
      throw const CliFailure(
        code: 'invalid_arguments',
        message: 'Invalid arguments.',
      );
    }
    final length = _boundedOption(
      arguments,
      'length',
      min: 32,
      max: 1024,
      defaultValue: 32,
    );
    return service.createKey(length: length);
  }

  Future<CommandResult> _runUri(ArgResults arguments) async {
    if (arguments.rest.isNotEmpty) {
      throw const CliFailure(
        code: 'invalid_arguments',
        message: 'Invalid arguments.',
      );
    }
    final kind = OtpKind.parseCli(arguments.option('type'));
    final provided = _providedOtpOptions(arguments);
    validateOtpOptionCompatibility(
      kind: kind,
      uriInput: false,
      provided: provided,
    );
    final account = arguments.option('account');
    if (account == null) {
      throw const CliFailure(
        code: 'missing_option',
        message: 'Missing required option.',
        details: <String, Object?>{'option': 'account'},
      );
    }
    final credential = await CredentialReader(
      environment: environment,
      input: input,
    ).read(_credentialOptions(arguments, allowUri: false));
    final digits = _boundedOption(
      arguments,
      'digits',
      min: 6,
      max: 8,
      defaultValue: 6,
    );
    final algorithm = OtpHash.parseCli(arguments.option('algorithm'));
    if (kind == OtpKind.totp) {
      return service.createTotpUri(
        TotpConfig(
          secret: credential.value,
          digits: digits,
          algorithm: algorithm,
          period: _boundedOption(
            arguments,
            'period',
            min: 1,
            max: 86400,
            defaultValue: 30,
          ),
        ),
        issuer: arguments.option('issuer'),
        account: account,
      );
    }
    return service.createHotpUri(
      HotpConfig(
        secret: credential.value,
        digits: digits,
        algorithm: algorithm,
        counter: _boundedOption(
          arguments,
          'counter',
          min: 0,
          max: maxHotpCounter,
          defaultValue: 0,
        ),
      ),
      issuer: arguments.option('issuer'),
      account: account,
    );
  }
}

ArgParser _buildParser() {
  final parser = ArgParser(usageLineLength: 80)
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Show this help text.',
    )
    ..addFlag(
      'version',
      negatable: false,
      help: 'Show the installed toto version.',
    );
  _addFormatOption(parser);
  for (final command in <String>['code', 'generate']) {
    parser.addCommand(command, _otpParser(check: false));
  }
  for (final command in <String>['check', 'verify']) {
    parser.addCommand(command, _otpParser(check: true));
  }
  for (final command in <String>['key', 'secret']) {
    parser.addCommand(command, _keyParser());
  }
  parser.addCommand('uri', _uriParser());
  return parser;
}

ArgParser _otpParser({required bool check}) {
  final parser = ArgParser(usageLineLength: 80)
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Show command help.',
    );
  _addCredentialOptions(parser, allowUri: true);
  _addOtpOptions(parser);
  if (check) {
    parser.addOption(
      'window',
      valueHelp: 'STEPS',
      help: 'Verification window from 0 through 10 (default: 0).',
    );
  }
  _addFormatOption(parser);
  return parser;
}

ArgParser _keyParser() {
  final parser = ArgParser(usageLineLength: 80)
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Show command help.',
    )
    ..addOption(
      'length',
      valueHelp: 'CHARS',
      help: 'Base32 length, 32..1024 and a multiple of 8 (default: 32).',
    );
  _addFormatOption(parser);
  return parser;
}

ArgParser _uriParser() {
  final parser = ArgParser(usageLineLength: 80)
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Show command help.',
    );
  _addCredentialOptions(parser, allowUri: false);
  _addOtpOptions(parser, includeAt: false);
  parser
    ..addOption(
      'issuer',
      valueHelp: 'NAME',
      help: 'Optional non-empty provider name.',
    )
    ..addOption(
      'account',
      valueHelp: 'LABEL',
      help: 'Required non-empty account label.',
    );
  _addFormatOption(parser);
  return parser;
}

void _addCredentialOptions(ArgParser parser, {required bool allowUri}) {
  parser
    ..addOption(
      'secret',
      valueHelp: 'BASE32',
      help: 'Read a canonical Base32 secret directly.',
    )
    ..addOption(
      'secret-env',
      valueHelp: 'NAME',
      help: 'Read a Base32 secret from an environment variable.',
    )
    ..addFlag(
      'secret-stdin',
      negatable: false,
      help: 'Read a Base32 secret from standard input.',
    );
  if (allowUri) {
    parser
      ..addOption(
        'uri',
        valueHelp: 'URI',
        help: 'Read an otpauth:// URI directly.',
      )
      ..addOption(
        'uri-env',
        valueHelp: 'NAME',
        help: 'Read an otpauth:// URI from an environment variable.',
      )
      ..addFlag(
        'uri-stdin',
        negatable: false,
        help: 'Read an otpauth:// URI from standard input.',
      );
  }
}

void _addOtpOptions(ArgParser parser, {bool includeAt = true}) {
  parser
    ..addOption(
      'type',
      valueHelp: 'TYPE',
      help: 'OTP type: totp or hotp (default: totp).',
    )
    ..addOption(
      'digits',
      valueHelp: 'COUNT',
      help: 'Code length from 6 through 8 (default: 6).',
    )
    ..addOption(
      'algorithm',
      valueHelp: 'HASH',
      help: 'HMAC hash: sha1, sha256, sha384, or sha512 (default: sha1).',
    )
    ..addOption(
      'period',
      valueHelp: 'SECONDS',
      help: 'TOTP period from 1 through 86400 (default: 30).',
    )
    ..addOption(
      'counter',
      valueHelp: 'VALUE',
      help: 'Non-negative HOTP counter.',
    );
  if (includeAt) {
    parser.addOption(
      'at',
      valueHelp: 'TIME',
      help: 'TOTP time as Unix seconds or timezone-qualified RFC 3339.',
    );
  }
}

void _addFormatOption(ArgParser parser) {
  parser.addOption(
    'format',
    valueHelp: 'FORMAT',
    help: 'Output as text, json, or lon (default: text).',
  );
}

CredentialOptions _credentialOptions(
  ArgResults arguments, {
  required bool allowUri,
}) =>
    CredentialOptions(
      secret: arguments.option('secret'),
      secretEnv: arguments.option('secret-env'),
      secretStdin: arguments.flag('secret-stdin'),
      uri: allowUri ? arguments.option('uri') : null,
      uriEnv: allowUri ? arguments.option('uri-env') : null,
      uriStdin: allowUri && arguments.flag('uri-stdin'),
    );

Set<String> _providedOtpOptions(ArgResults arguments) => <String>{
      for (final name in <String>[
        'type',
        'digits',
        'algorithm',
        'period',
        'counter',
        if (arguments.options.contains('at')) 'at',
      ])
        if (arguments.wasParsed(name)) name,
    };

void _validateRawOtpOptionsBeforeRead(
  ArgResults arguments,
  Set<String> provided,
) {
  final kind = OtpKind.parseCli(arguments.option('type'));
  validateOtpOptionCompatibility(
    kind: kind,
    uriInput: false,
    provided: provided,
  );
  if (kind == OtpKind.hotp && !arguments.wasParsed('counter')) {
    throw const CliFailure(
      code: 'missing_option',
      message: 'Missing required option.',
      details: <String, Object?>{'option': 'counter'},
    );
  }
}

int _boundedOption(
  ArgResults arguments,
  String name, {
  required int min,
  required int max,
  int? defaultValue,
}) {
  final value = arguments.option(name);
  if (value == null) {
    if (defaultValue != null) {
      return defaultValue;
    }
    throw CliFailure(
      code: 'missing_option',
      message: 'Missing required option.',
      details: <String, Object?>{'option': name},
    );
  }
  return parseBoundedInt(value, option: name, min: min, max: max);
}

String _canonicalCommand(String name) => switch (name) {
      'generate' => 'code',
      'verify' => 'check',
      'secret' => 'key',
      _ => name,
    };

const _singleValueOptions = <String>{
  'secret',
  'secret-env',
  'uri',
  'uri-env',
  'type',
  'digits',
  'algorithm',
  'period',
  'counter',
  'at',
  'window',
  'length',
  'issuer',
  'account',
};

bool _hasRepeatedSingleValueOption(List<String> arguments) {
  final seen = <String>{};
  for (final argument in arguments) {
    if (argument == '--') {
      break;
    }
    if (!argument.startsWith('--')) {
      continue;
    }
    final separator = argument.indexOf('=');
    final name = argument.substring(
      2,
      separator == -1 ? argument.length : separator,
    );
    if (_singleValueOptions.contains(name) && !seen.add(name)) {
      return true;
    }
  }
  return false;
}

String _rootHelp(ArgParser parser) => '''
toto — AI-first TOTP and HOTP CLI

Usage: toto <command> [options]

Commands:
  code      Generate an OTP code (alias: generate)
  check     Verify an OTP code (alias: verify)
  key       Generate a shared secret (alias: secret)
  uri       Generate an otpauth:// provisioning URI

Global options:
${parser.usage}
''';

String _commandHelp(String command) {
  final parser = switch (command) {
    'code' => _otpParser(check: false),
    'check' => _otpParser(check: true),
    'key' => _keyParser(),
    'uri' => _uriParser(),
    _ => ArgParser(),
  };
  final description = switch (command) {
    'code' => 'Generate a TOTP or HOTP code.',
    'check' => 'Verify a TOTP or HOTP code.',
    'key' => 'Generate a cryptographically secure Base32 secret.',
    'uri' => 'Generate an otpauth:// provisioning URI.',
    _ => '',
  };
  final usage = command == 'check'
      ? 'toto check <code> [options]'
      : 'toto $command [options]';
  return '''
toto $command — $description

Usage: $usage

Options:
${parser.usage}
''';
}

final class _FormatScan {
  const _FormatScan({
    required this.arguments,
    required this.format,
    required this.invalid,
  });

  factory _FormatScan.scan(List<String> source) {
    final arguments = <String>[];
    final values = <String>[];
    var malformed = false;
    var optionsEnded = false;
    for (var index = 0; index < source.length; index++) {
      final argument = source[index];
      if (optionsEnded) {
        arguments.add(argument);
        continue;
      }
      if (argument == '--') {
        optionsEnded = true;
        arguments.add(argument);
        continue;
      }
      if (argument == '--format') {
        if (index + 1 >= source.length || source[index + 1].startsWith('--')) {
          malformed = true;
          continue;
        }
        values.add(source[++index]);
        continue;
      }
      if (argument.startsWith('--format=')) {
        values.add(argument.substring('--format='.length));
        continue;
      }
      arguments.add(argument);
    }
    final validValues = values.where(
      (value) => value == 'text' || value == 'json' || value == 'lon',
    );
    final unique = validValues.toSet();
    final allValid = validValues.length == values.length;
    final unambiguous = allValid && unique.length == 1;
    final invalid = malformed || !allValid || values.length > 1;
    return _FormatScan(
      arguments: arguments,
      format:
          unambiguous ? OutputFormat.parse(unique.single) : OutputFormat.text,
      invalid: invalid,
    );
  }

  final List<String> arguments;
  final OutputFormat format;
  final bool invalid;
}
