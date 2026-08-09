/// Programmatic entry point for the AI-first `toto` OTP command-line tool.
///
/// Use [runToto] to invoke the same command contract as the `toto` executable
/// while injecting I/O, environment variables, and time for deterministic
/// automation and testing.
library;

import 'dart:io';

import 'src/cli/toto_runner.dart';

/// Runs the `toto` CLI with optional process dependency overrides.
///
/// Returns `0` for success, `1` when a well-formed code does not match, `2`
/// for usage or input errors, and `70` for unexpected internal failures.
/// Success output is written to [output], while diagnostics are written to
/// [errorOutput]. When omitted, dependencies use the current process values.
Future<int> runToto(
  List<String> arguments, {
  Stream<List<int>>? input,
  StringSink? output,
  StringSink? errorOutput,
  Map<String, String>? environment,
  DateTime Function()? now,
}) =>
    TotoRunner(
      input: input ?? stdin,
      output: output ?? stdout,
      errorOutput: errorOutput ?? stderr,
      environment: environment ?? Platform.environment,
      now: now ?? DateTime.now,
    ).run(arguments);
