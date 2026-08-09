import 'dart:convert';

import '../otp/otp_config.dart';
import 'cli_failure.dart';

enum CredentialKind { secret, uri }

final class CredentialValue {
  const CredentialValue({required this.kind, required this.value});

  final CredentialKind kind;
  final String value;
}

final class CredentialOptions {
  const CredentialOptions({
    this.secret,
    this.secretEnv,
    this.secretStdin = false,
    this.uri,
    this.uriEnv,
    this.uriStdin = false,
  });

  final String? secret;
  final String? secretEnv;
  final bool secretStdin;
  final String? uri;
  final String? uriEnv;
  final bool uriStdin;

  int get selectedSourceCount => <bool>[
        secret != null,
        secretEnv != null,
        secretStdin,
        uri != null,
        uriEnv != null,
        uriStdin,
      ].where((selected) => selected).length;

  bool get hasUriSource => uri != null || uriEnv != null || uriStdin;

  bool get hasSecretSource =>
      secret != null || secretEnv != null || secretStdin;
}

final class CredentialReader {
  const CredentialReader({
    required this.environment,
    required this.input,
  });

  final Map<String, String> environment;
  final Stream<List<int>> input;

  Future<CredentialValue> read(CredentialOptions options) async {
    final sources = <_SelectedSource>[
      if (options.secret != null)
        _SelectedSource.direct(
          name: 'secret',
          kind: CredentialKind.secret,
          value: options.secret!,
        ),
      if (options.secretEnv != null)
        _SelectedSource.environment(
          name: 'secret-env',
          kind: CredentialKind.secret,
          key: options.secretEnv!,
        ),
      if (options.secretStdin)
        const _SelectedSource.stdin(
          name: 'secret-stdin',
          kind: CredentialKind.secret,
        ),
      if (options.uri != null)
        _SelectedSource.direct(
          name: 'uri',
          kind: CredentialKind.uri,
          value: options.uri!,
        ),
      if (options.uriEnv != null)
        _SelectedSource.environment(
          name: 'uri-env',
          kind: CredentialKind.uri,
          key: options.uriEnv!,
        ),
      if (options.uriStdin)
        const _SelectedSource.stdin(
          name: 'uri-stdin',
          kind: CredentialKind.uri,
        ),
    ];

    if (sources.isEmpty) {
      throw const CliFailure(
        code: 'missing_option',
        message: 'Missing required option.',
        details: <String, Object?>{'option': 'credential'},
      );
    }
    if (sources.length > 1) {
      throw CliFailure(
        code: 'conflicting_options',
        message: 'Conflicting options.',
        details: <String, Object?>{
          'options': sources.map((source) => source.name).toList()..sort(),
        },
      );
    }

    final source = sources.single;
    final raw = switch (source.sourceKind) {
      _SourceKind.direct => source.value!,
      _SourceKind.environment => _readEnvironment(source),
      _SourceKind.stdin => await _readStdin(source.kind),
    };
    final value = source.kind == CredentialKind.secret
        ? validateSecret(raw)
        : _validateUriLength(raw);
    return CredentialValue(kind: source.kind, value: value);
  }

  String _readEnvironment(_SelectedSource source) {
    final value = environment[source.value!];
    final safeSource =
        source.kind == CredentialKind.secret ? 'secret_env' : 'uri_env';
    if (value == null) {
      throw CliFailure(
        code: 'missing_environment',
        message: 'Environment value is missing.',
        details: <String, Object?>{'source': safeSource},
      );
    }
    if (value.isEmpty) {
      throw CliFailure(
        code: 'empty_environment',
        message: 'Environment value is empty.',
        details: <String, Object?>{'source': safeSource},
      );
    }
    return value;
  }

  Future<String> _readStdin(CredentialKind kind) async {
    final buffer = StringBuffer();
    var length = 0;
    try {
      await for (final chunk in utf8.decoder.bind(input)) {
        length += chunk.length;
        if (length > 16384) {
          throw CliFailure(
            code: 'input_too_large',
            message: 'Input is too large.',
            details: <String, Object?>{
              'source': 'stdin',
              'maxCodeUnits': 16384,
            },
          );
        }
        buffer.write(chunk);
      }
    } on FormatException {
      throw const CliFailure(
        code: 'invalid_arguments',
        message: 'Invalid arguments.',
      );
    }
    var value = buffer.toString();
    if (value.endsWith('\r\n')) {
      value = value.substring(0, value.length - 2);
    } else if (value.endsWith('\n')) {
      value = value.substring(0, value.length - 1);
    }
    if (value.isEmpty) {
      throw CliFailure(
        code: 'empty_stdin',
        message: 'Standard input is empty.',
        details: <String, Object?>{
          'source': kind == CredentialKind.secret ? 'secret' : 'uri',
        },
      );
    }
    return value;
  }

  String _validateUriLength(String value) {
    if (value.length > 16384) {
      throw const CliFailure(
        code: 'input_too_large',
        message: 'Input is too large.',
        details: <String, Object?>{
          'source': 'uri',
          'maxCodeUnits': 16384,
        },
      );
    }
    return value;
  }
}

enum _SourceKind { direct, environment, stdin }

final class _SelectedSource {
  const _SelectedSource._({
    required this.name,
    required this.kind,
    required this.sourceKind,
    this.value,
  });

  const _SelectedSource.direct({
    required String name,
    required CredentialKind kind,
    required String value,
  }) : this._(
          name: name,
          kind: kind,
          sourceKind: _SourceKind.direct,
          value: value,
        );

  const _SelectedSource.environment({
    required String name,
    required CredentialKind kind,
    required String key,
  }) : this._(
          name: name,
          kind: kind,
          sourceKind: _SourceKind.environment,
          value: key,
        );

  const _SelectedSource.stdin({
    required String name,
    required CredentialKind kind,
  }) : this._(
          name: name,
          kind: kind,
          sourceKind: _SourceKind.stdin,
        );

  final String name;
  final CredentialKind kind;
  final _SourceKind sourceKind;
  final String? value;
}
