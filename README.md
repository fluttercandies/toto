<p align="center">
  <img src="assets/logo.png" alt="toto logo" width="144">
</p>

<h1 align="center">toto</h1>

<p align="center">
  An AI-first TOTP and HOTP command-line tool with deterministic text, JSON, and LON output.
</p>

<p align="center">
  <a href="https://pub.dev/packages/toto"><img alt="Pub version" src="https://img.shields.io/pub/v/toto.svg?style=flat-square"></a>
  <a href="https://github.com/fluttercandies/toto/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/fluttercandies/toto/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pub.dev/packages/toto/score"><img alt="Pub points" src="https://img.shields.io/pub/points/toto.svg?style=flat-square"></a>
  <a href="https://pub.dev/packages/toto/score"><img alt="Pub likes" src="https://img.shields.io/pub/likes/toto.svg?style=flat-square"></a>
  <img alt="Dart SDK 3.3 or later" src="https://img.shields.io/badge/Dart-%E2%89%A53.3.0-0175C2?style=flat-square&amp;logo=dart&amp;logoColor=white">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-2EA44F?style=flat-square"></a>
  <a href="https://github.com/fluttercandies/toto"><img alt="GitHub source" src="https://img.shields.io/badge/source-GitHub-181717?style=flat-square&amp;logo=github&amp;logoColor=white"></a>
</p>

<p align="center">
  <strong>English</strong> · <a href="README.zh-CN.md">简体中文</a>
</p>

`toto` generates and verifies [TOTP (RFC 6238)](https://www.rfc-editor.org/rfc/rfc6238) and [HOTP (RFC 4226)](https://www.rfc-editor.org/rfc/rfc4226) codes. It is designed for shell users, CI jobs, scripts, and AI agents: every operation is non-interactive, errors are stable, credentials can avoid argv, and time can be pinned for deterministic execution.

## Why toto

- Short, explicit commands: `code`, `check`, `key`, and `uri`.
- TOTP and HOTP with SHA-1, SHA-256, SHA-384, or SHA-512 and 6–8 digits.
- Plain text for pipes; compact JSON and [LON](https://pub.dev/packages/lon) for agents and automation.
- Stable `schemaVersion: 1` success and error envelopes.
- Reproducible TOTP operations with RFC 3339 or Unix-second `--at` values.
- Direct, environment, and stdin credential sources with mutual-exclusion checks.
- Strict Base32 and `otpauth://` validation instead of silent normalization.
- Deliberate exit codes for reliable branching.

## Requirements and installation

`toto` supports Dart `>=3.3.0 <4.0.0`. Dart 3.3 is the minimum supported version because it is also the minimum supported by `lon 1.0.1`; lowering the constraint would be inaccurate.

Install the executable from pub.dev:

```sh
dart pub global activate toto
```

Make sure Dart's global executable directory is on `PATH`, then verify the installation:

```sh
toto --version
toto --help
```

## Quick start

Generate a new 160-bit Base32 secret:

```sh
toto key
```

Generate the current TOTP without placing the secret in argv:

```sh
printf '%s' "$OTP_SECRET" | toto code --secret-stdin
```

Get deterministic structured output:

```sh
toto code \
  --secret-env OTP_SECRET \
  --at 1970-01-01T00:00:59Z \
  --digits 8 \
  --format json
```

```json
{"schemaVersion":1,"status":"ok","command":"code","type":"totp","code":"94287082","algorithm":"sha1","digits":8,"period":30,"at":"1970-01-01T00:00:59Z","validFor":1}
```

The example uses the RFC test secret `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` in `OTP_SECRET`.

## Commands

| Command | Alias | Purpose | Text output |
|---|---|---|---|
| `toto code` | `generate` | Generate a TOTP or HOTP code | Code only |
| `toto check <code>` | `verify` | Verify a TOTP or HOTP code | `true` or `false` |
| `toto key` | `secret` | Generate a cryptographically secure Base32 secret | Secret only |
| `toto uri` | — | Generate an `otpauth://` provisioning URI | URI only |

Aliases are accepted for human convenience. Structured output always reports the canonical command name: `code`, `check`, `key`, or `uri`.

### Generate a code

TOTP is the default type:

```sh
toto code --secret-env OTP_SECRET
toto code --secret-env OTP_SECRET --at 1735689600
toto code --secret-env OTP_SECRET --digits 8 --algorithm sha256 --period 60
```

HOTP requires a counter when a raw secret is used:

```sh
toto code --type hotp --secret-env OTP_SECRET --counter 42
```

An `otpauth://` URI supplies the token configuration. A HOTP URI's counter may be overridden at runtime; other URI configuration cannot be mixed with explicit `--type`, `--digits`, `--algorithm`, or `--period` values.

```sh
toto code --uri-env OTP_URI
toto code --uri-env HOTP_URI --counter 43
```

### Verify a code

```sh
toto check 94287082 \
  --secret-env OTP_SECRET \
  --digits 8 \
  --at 59
```

`--window` defaults to `0` and accepts `0..10`. For TOTP it checks neighbouring time steps in the order `0, -1, +1, -2, +2, ...`; for HOTP it checks forward counters. A correctly shaped but non-matching code prints `false` and exits with `1`. A malformed code is an input error and exits with `2`.

HOTP verification returns the actual matched and next counters in structured output:

```sh
toto check 755224 \
  --type hotp \
  --secret-env OTP_SECRET \
  --counter 0 \
  --window 3 \
  --format json
```

After a successful HOTP check, atomically persist `nextCounter`. Reusing the old counter permits replay; `toto` reports state but intentionally does not own your storage.

### Generate a secret

```sh
toto key
toto key --length 64 --format json
```

`--length` defaults to 32 Base32 characters (160 bits) and must be a multiple of 8 from 32 through 1024. Secrets are generated by `dart_dash_otp` with a cryptographically secure random source.

### Generate a provisioning URI

```sh
toto uri \
  --secret-env OTP_SECRET \
  --issuer Example \
  --account alice@example.com
```

```text
otpauth://totp/Example:alice%40example.com?secret=...&issuer=Example&digits=6&algorithm=SHA1&period=30
```

For HOTP:

```sh
toto uri \
  --type hotp \
  --secret-env OTP_SECRET \
  --issuer Example \
  --account alice@example.com \
  --counter 0
```

The default SHA-1, 6-digit, 30-second TOTP profile follows the Google Authenticator Key URI format and has the broadest authenticator compatibility. SHA-256/SHA-384/SHA-512, 7–8 digits, custom periods, and HOTP are standards-based but are not supported consistently by every authenticator; confirm support in the target application.

## Credential input

Select exactly one credential source per command:

| Value | Direct | Environment | Stdin |
|---|---|---|---|
| Base32 secret | `--secret VALUE` | `--secret-env NAME` | `--secret-stdin` |
| OTP URI (`code`/`check`) | `--uri VALUE` | `--uri-env NAME` | `--uri-stdin` |

Prefer environment or stdin sources. Direct values may be retained in shell history and exposed in process listings.

Secrets must be canonical uppercase, unpadded Base32 using only `A-Z2-7`, including zero unused pad bits. `toto` rejects lowercase, whitespace, `=` padding, non-canonical aliases, and invalid characters rather than silently changing the credential. Stdin removes at most one final LF or CRLF; all other whitespace remains significant.

## Output formats

Use `--format text|json|lon` anywhere in the invocation. `text` is the default.

```sh
toto code --secret-env OTP_SECRET --at 59 --digits 8 --format text
# 94287082

toto code --secret-env OTP_SECRET --at 59 --digits 8 --format lon
# {schemaVersion:1 status:ok command:code type:totp code:"94287082" algorithm:sha1 digits:8 period:30 at:"1970-01-01T00:00:59Z" validFor:1}
```

JSON and LON serialize the same ordered data model. LON is the compact, canonical, lossless text encoding of the JSON data model provided by `lon`; `toto` calls `lon.encode` rather than maintaining a custom serializer.

Structured output is one line with one trailing newline and no ANSI styling. The schemas are stable for `schemaVersion: 1`:

| Result | Fields after `schemaVersion`, `status`, and `command` |
|---|---|
| TOTP `code` | `type`, `code`, `algorithm`, `digits`, `period`, `at`, `validFor` |
| HOTP `code` | `type`, `code`, `algorithm`, `digits`, `counter` |
| TOTP `check` | `type`, `valid`, `algorithm`, `digits`, `period`, `at`, `window`, `matchedOffset`, `matchedAt` |
| HOTP `check` | `type`, `valid`, `algorithm`, `digits`, `counter`, `window`, `matchedCounter`, `nextCounter` |
| `key` | `secret`, `length`, `entropyBits` |
| TOTP `uri` | `type`, `uri`, `algorithm`, `digits`, `issuer`, `account`, `period` |
| HOTP `uri` | `type`, `uri`, `algorithm`, `digits`, `issuer`, `account`, `counter` |

Errors use a separate stable envelope on stderr:

```json
{"schemaVersion":1,"status":"error","error":{"code":"missing_option","message":"Missing required option.","details":{"option":"counter"}}}
```

## AI and automation patterns

Recommended agent contract:

1. Use the canonical short command.
2. Use `--format json` or `--format lon`.
3. Pass credentials through a pre-populated environment variable or stdin.
4. Set `--at` whenever reproducibility matters.
5. Branch on the process exit code and `error.code`, not human-readable text.
6. Never log the `key` or `uri` success payload.

Example deterministic agent call:

```sh
toto code \
  --secret-env OTP_SECRET \
  --at 2026-08-09T12:00:00Z \
  --format json
```

No command prompts interactively, implicitly reads stdin, emits colors, or adds diagnostic noise to stdout. Stdin is read only when a `--secret-stdin` or `--uri-stdin` option is explicit. `--help` and `--version` remain human-readable regardless of `--format`.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Command succeeded; for `check`, the OTP is valid |
| `1` | `check` completed normally, but the OTP does not match |
| `2` | Usage, credential, URI, or OTP configuration error |
| `70` | Unexpected internal error |

Successful output goes to stdout. Errors and diagnostics go to stderr. Every non-help result is exactly one line.

## Security notes

- Prefer `--secret-env`, `--uri-env`, `--secret-stdin`, or `--uri-stdin`; direct credentials can leak through process metadata and shell history.
- Treat generated secrets and provisioning URIs as credentials. A URI contains the secret.
- Do not place secret-bearing JSON/LON responses in logs, prompts, traces, or build artifacts.
- Use a secret manager and restrict environment inheritance in multi-user environments.
- Synchronize system clocks for TOTP. Keep verification windows as small as operationally possible.
- Persist HOTP counters atomically after success and reject replayed counters.
- `toto` redacts input failures by constructing messages from fixed error codes and allowlisted details; it never intentionally echoes credential values on failure.

## Embedded use

The public `runToto` entry point supports injected stdin, stdout, stderr, environment, and clock values for deterministic embedding and testing:

```dart
import 'package:toto/toto.dart';

final exitCode = await runToto(
  ['code', '--secret-env', 'OTP_SECRET', '--at', '59', '--format', 'json'],
  environment: {'OTP_SECRET': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'},
);
```

## License

`toto` is available under the [MIT License](LICENSE).
