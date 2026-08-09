import 'dart:io';

import 'src/cli/toto_runner.dart';

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
