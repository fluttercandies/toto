import 'dart:io';

import 'package:toto/toto.dart';

Future<void> main() async {
  final status = await runToto(
    const [
      'code',
      '--secret-env',
      'TOTO_EXAMPLE_SECRET',
      '--digits',
      '8',
      '--at',
      '59',
      '--format',
      'json',
    ],
    environment: const {
      // RFC 6238 Appendix B test secret. Never hard-code real credentials.
      'TOTO_EXAMPLE_SECRET': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    },
  );

  if (status != 0) {
    exitCode = status;
  }
}
