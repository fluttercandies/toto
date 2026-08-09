import 'dart:convert';
import 'dart:io';

import 'package:lon/lon.dart';
import 'package:test/test.dart';

void main() {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  Future<ProcessResult> run(List<String> arguments) => Process.run(
        Platform.resolvedExecutable,
        <String>['run', 'bin/toto.dart', ...arguments],
        workingDirectory: Directory.current.path,
      );

  test('real process separates output and returns success', () async {
    final result = await run(<String>[
      'code',
      '--secret',
      secret,
      '--digits',
      '8',
      '--at',
      '59',
    ]);
    expect(result.exitCode, 0);
    expect(result.stdout, '94287082\n');
    expect(result.stderr, isEmpty);
  });

  test('real process returns predicate and usage exit codes', () async {
    final mismatch = await run(<String>[
      'check',
      '00000000',
      '--secret',
      secret,
      '--digits',
      '8',
      '--at',
      '59',
    ]);
    expect(mismatch.exitCode, 1);
    expect(mismatch.stdout, 'false\n');
    expect(mismatch.stderr, isEmpty);

    final invalid = await run(<String>['code']);
    expect(invalid.exitCode, 2);
    expect(invalid.stdout, isEmpty);
    expect(invalid.stderr, startsWith('error[missing_option]:'));
  });

  test('real process accepts stdin and emits JSON and LON', () async {
    final process = await Process.start(
      Platform.resolvedExecutable,
      <String>[
        'run',
        'bin/toto.dart',
        'code',
        '--format',
        'json',
        '--secret-stdin',
        '--digits',
        '8',
        '--at',
        '59',
      ],
      workingDirectory: Directory.current.path,
    );
    process.stdin.write('$secret\n');
    await process.stdin.close();
    final stdoutText = await utf8.decoder.bind(process.stdout).join();
    final stderrText = await utf8.decoder.bind(process.stderr).join();
    expect(await process.exitCode, 0);
    expect(stderrText, isEmpty);
    expect(
        (jsonDecode(stdoutText) as Map<String, Object?>)['code'], '94287082');

    final lonResult = await run(<String>[
      'code',
      '--format',
      'lon',
      '--secret',
      secret,
      '--at',
      '59',
    ]);
    expect(lonResult.exitCode, 0);
    expect(
      (lon.decode((lonResult.stdout as String).trim())
          as Map<Object?, Object?>)['command'],
      'code',
    );
  });

  test('real process exposes human help and version', () async {
    final help = await run(<String>['--help', '--format', 'json']);
    expect(help.exitCode, 0);
    expect(help.stdout, contains('code'));
    expect(help.stdout, contains('check'));
    expect(help.stderr, isEmpty);

    final version = await run(<String>['--version']);
    expect(version.exitCode, 0);
    expect(version.stdout, 'toto 1.0.1\n');
  });
}
