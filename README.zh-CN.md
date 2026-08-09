<p align="center">
  <img src="assets/logo.png" alt="toto logo" width="144">
</p>

<h1 align="center">toto</h1>

<p align="center">
  面向 AI 的 TOTP/HOTP 命令行工具，提供确定性的文本、JSON 与 LON 输出。
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
  <a href="README.md">English</a> · <strong>简体中文</strong>
</p>

`toto` 用于生成和校验 [TOTP（RFC 6238）](https://www.rfc-editor.org/rfc/rfc6238)与 [HOTP（RFC 4226）](https://www.rfc-editor.org/rfc/rfc4226)验证码。它面向命令行用户、CI、脚本和 AI Agent：全部操作均为非交互式，错误契约稳定，凭据可避开 argv，并可固定时间以获得确定性结果。

## 为什么选择 toto

- 短而明确的命令：`code`、`check`、`key`、`uri`。
- 支持 TOTP/HOTP、SHA-1/SHA-256/SHA-384/SHA-512 与 6–8 位验证码。
- 文本适合管道；紧凑 JSON 和 [LON](https://pub.dev/packages/lon) 适合 Agent 与自动化。
- 稳定的 `schemaVersion: 1` 成功和错误信封。
- 通过 RFC 3339 或 Unix 秒 `--at` 参数实现可复现 TOTP 操作。
- 支持直接参数、环境变量和 stdin 凭据来源，并执行互斥校验。
- 严格校验 Base32 与 `otpauth://` URI，不做静默规范化。
- 明确的退出码便于可靠分支。

## 环境要求与安装

`toto` 支持 Dart `>=3.3.0 <4.0.0`。Dart 3.3 也是 `lon 1.0.1` 支持的最低版本，因此继续降低约束会与真实依赖能力不符。

从 pub.dev 安装可执行文件：

```sh
dart pub global activate toto
```

确保 Dart 全局可执行文件目录位于 `PATH`，然后验证安装：

```sh
toto --version
toto --help
```

## 快速开始

生成新的 160 位 Base32 密钥：

```sh
toto key
```

生成当前 TOTP，同时避免将密钥放入 argv：

```sh
printf '%s' "$OTP_SECRET" | toto code --secret-stdin
```

获取确定性的结构化输出：

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

该示例在 `OTP_SECRET` 中使用 RFC 测试密钥 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`。

## 命令

| 命令 | 别名 | 用途 | 文本输出 |
|---|---|---|---|
| `toto code` | `generate` | 生成 TOTP 或 HOTP 验证码 | 仅验证码 |
| `toto check <code>` | `verify` | 校验 TOTP 或 HOTP 验证码 | `true` 或 `false` |
| `toto key` | `secret` | 生成密码学安全的 Base32 密钥 | 仅密钥 |
| `toto uri` | — | 生成 `otpauth://` 配置 URI | 仅 URI |

长别名方便已有习惯的用户；结构化输出始终报告主命令名 `code`、`check`、`key` 或 `uri`。

### 生成验证码

默认类型为 TOTP：

```sh
toto code --secret-env OTP_SECRET
toto code --secret-env OTP_SECRET --at 1735689600
toto code --secret-env OTP_SECRET --digits 8 --algorithm sha256 --period 60
```

使用原始密钥时，HOTP 必须提供 counter：

```sh
toto code --type hotp --secret-env OTP_SECRET --counter 42
```

`otpauth://` URI 会提供 token 配置。运行时可以覆盖 HOTP URI 的 counter；其他 URI 配置不得与显式 `--type`、`--digits`、`--algorithm` 或 `--period` 混用。

```sh
toto code --uri-env OTP_URI
toto code --uri-env HOTP_URI --counter 43
```

### 校验验证码

```sh
toto check 94287082 \
  --secret-env OTP_SECRET \
  --digits 8 \
  --at 59
```

`--window` 默认为 `0`，可取 `0..10`。TOTP 按 `0, -1, +1, -2, +2, ...` 的顺序检查相邻时间步；HOTP 向前检查 counter。格式正确但不匹配的验证码输出 `false` 并以 `1` 退出；格式错误属于输入错误，以 `2` 退出。

HOTP 校验会在结构化输出中返回实际匹配 counter 与下一个 counter：

```sh
toto check 755224 \
  --type hotp \
  --secret-env OTP_SECRET \
  --counter 0 \
  --window 3 \
  --format json
```

HOTP 校验成功后，应以原子方式持久化 `nextCounter`。复用旧 counter 会允许重放；`toto` 负责报告状态，但不会接管你的存储。

### 生成密钥

```sh
toto key
toto key --length 64 --format json
```

`--length` 默认为 32 个 Base32 字符（160 位），必须是 32 到 1024 之间的 8 的倍数。密钥由 `dart_dash_otp` 使用密码学安全随机源生成。

### 生成配置 URI

```sh
toto uri \
  --secret-env OTP_SECRET \
  --issuer Example \
  --account alice@example.com
```

```text
otpauth://totp/Example:alice%40example.com?secret=...&issuer=Example&digits=6&algorithm=SHA1&period=30
```

HOTP 示例：

```sh
toto uri \
  --type hotp \
  --secret-env OTP_SECRET \
  --issuer Example \
  --account alice@example.com \
  --counter 0
```

默认的 SHA-1、6 位、30 秒 TOTP 配置遵循 Google Authenticator Key URI Format，兼容性最广。SHA-256/SHA-384/SHA-512、7–8 位、自定义 period 和 HOTP 都有标准依据，但并非所有 authenticator 都完整支持；请确认目标应用的能力。

## 凭据输入

每次调用必须且只能选择一种凭据来源：

| 值 | 直接参数 | 环境变量 | Stdin |
|---|---|---|---|
| Base32 密钥 | `--secret VALUE` | `--secret-env NAME` | `--secret-stdin` |
| OTP URI（`code`/`check`） | `--uri VALUE` | `--uri-env NAME` | `--uri-stdin` |

优先使用环境变量或 stdin。直接传值可能被 shell 历史和进程列表保留。

密钥必须是规范的大写、无 padding Base32，只能使用 `A-Z2-7`，且未使用的 pad bit 必须为零。`toto` 会拒绝小写、空白、`=` padding、非规范等价值和非法字符，而不是静默修改凭据。Stdin 最多移除一个末尾 LF 或 CRLF；其他空白均有意义。

## 输出格式

可在命令任意位置使用 `--format text|json|lon`，默认是 `text`。

```sh
toto code --secret-env OTP_SECRET --at 59 --digits 8 --format text
# 94287082

toto code --secret-env OTP_SECRET --at 59 --digits 8 --format lon
# {schemaVersion:1 status:ok command:code type:totp code:"94287082" algorithm:sha1 digits:8 period:30 at:"1970-01-01T00:00:59Z" validFor:1}
```

JSON 与 LON 序列化同一个有序数据模型。LON 是由 `lon` 包提供的、针对 JSON 数据模型的紧凑、规范、无损文本编码；`toto` 直接调用 `lon.encode`，不维护自定义序列化器。

结构化输出始终为单行、带一个结尾换行且不包含 ANSI 样式。`schemaVersion: 1` 的稳定 schema 如下：

| 结果 | `schemaVersion`、`status`、`command` 之后的字段 |
|---|---|
| TOTP `code` | `type`、`code`、`algorithm`、`digits`、`period`、`at`、`validFor` |
| HOTP `code` | `type`、`code`、`algorithm`、`digits`、`counter` |
| TOTP `check` | `type`、`valid`、`algorithm`、`digits`、`period`、`at`、`window`、`matchedOffset`、`matchedAt` |
| HOTP `check` | `type`、`valid`、`algorithm`、`digits`、`counter`、`window`、`matchedCounter`、`nextCounter` |
| `key` | `secret`、`length`、`entropyBits` |
| TOTP `uri` | `type`、`uri`、`algorithm`、`digits`、`issuer`、`account`、`period` |
| HOTP `uri` | `type`、`uri`、`algorithm`、`digits`、`issuer`、`account`、`counter` |

错误会通过 stderr 使用独立的稳定信封：

```json
{"schemaVersion":1,"status":"error","error":{"code":"missing_option","message":"Missing required option.","details":{"option":"counter"}}}
```

## AI 与自动化范式

推荐的 Agent 契约：

1. 使用规范的短命令。
2. 使用 `--format json` 或 `--format lon`。
3. 通过预先注入的环境变量或 stdin 传递凭据。
4. 需要可复现结果时设置 `--at`。
5. 根据进程退出码和 `error.code` 分支，不解析人类文案。
6. 绝不记录 `key` 或 `uri` 的成功结果。

确定性 Agent 调用示例：

```sh
toto code \
  --secret-env OTP_SECRET \
  --at 2026-08-09T12:00:00Z \
  --format json
```

所有命令都不会交互式提示、隐式读取 stdin、输出颜色或向 stdout 添加诊断噪声。只有显式使用 `--secret-stdin` 或 `--uri-stdin` 时才会读取 stdin。`--help` 与 `--version` 无论 `--format` 为何都保持人类可读格式。

## 退出码

| 代码 | 含义 |
|---:|---|
| `0` | 命令成功；对 `check` 表示验证码有效 |
| `1` | `check` 正常完成，但验证码不匹配 |
| `2` | 用法、凭据、URI 或 OTP 配置错误 |
| `70` | 未预期内部错误 |

成功结果写 stdout；错误和诊断写 stderr。除 help 外，每个结果都严格输出一行。

## 安全说明

- 优先使用 `--secret-env`、`--uri-env`、`--secret-stdin` 或 `--uri-stdin`；直接凭据可能通过进程元数据和 shell 历史泄露。
- 将生成的密钥与配置 URI 都视为凭据；URI 包含密钥。
- 不要把包含密钥的 JSON/LON 结果写入日志、Prompt、Trace 或构建产物。
- 使用密钥管理器，并在多用户环境中限制环境变量继承。
- TOTP 需要系统时钟同步；校验 window 应保持在业务允许的最小值。
- HOTP 成功后必须原子持久化 counter，并拒绝重放旧 counter。
- `toto` 使用固定错误 code 和白名单 details 构造输入错误，失败时不会有意回显凭据值。

## 嵌入使用

公开的 `runToto` 入口支持注入 stdin、stdout、stderr、环境变量和时钟，便于确定性嵌入与测试：

```dart
import 'package:toto/toto.dart';

final exitCode = await runToto(
  ['code', '--secret-env', 'OTP_SECRET', '--at', '59', '--format', 'json'],
  environment: {'OTP_SECRET': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'},
);
```

## 许可证

`toto` 使用 [MIT License](LICENSE) 开源。
