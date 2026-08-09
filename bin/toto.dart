import 'dart:io' as io;

import 'package:toto/toto.dart';

Future<void> main(List<String> arguments) async {
  io.exitCode = await runToto(arguments);
  await io.stdout.flush();
  await io.stderr.flush();
}
