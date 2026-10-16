# XCS Android 业务重建与逆向分析

本仓库公开当前可编辑的 Java Android 重建工程、回归测试、逆向提取工具和分析报告。工程依据已有二进制证据重新实现业务逻辑，**没有恢复完整的原始 Dart / Rust / Go 源码，也没有证明全部行为与原 App 等价**。剩余边界见 `evidence/gap_progress.json`、`reverse/reports/逆向完整性审计与补齐报告.txt` 和 `reverse/reports/coverage_ledger.historical.json`。

## APP 全量工作区

已补充完整 `APP/` 工作区的原路径快照：**42,534 个文件、4,321 个目录，源文件共 3,153,516,657 字节**。原 APK、SO/DEX、解包与反编译输出、参考 SDK、工具 Git 历史、全部构建/交付产物、日志、模拟器磁盘、私钥和签名文件都在全量快照中。用户已明确确认私钥与生产凭据也公开，本次没有继续使用首版源码发布的排除规则。

完整归档为 1,843,151,831 字节，以 7 个 Git LFS 分卷上传。逐文件哈希、原始快照校验和恢复方法见 [`full-workspace/README.md`](full-workspace/README.md)。解压后保留 `APP/` 原路径，包括上传前的 `APP/public/` 发布副本及其 Git 状态。根目录可直接查看和编译的重建工程继续保留；以下构建命令适用于这部分工程。

## 工程内容

- `app/src/main/java/`：登录、HTTP、WebSocket、认证与心跳、断线重连、预览结束回调、识别校验与上传、设置和模型转换等已确认逻辑，以及 Java Android 界面。
- `evidence/`：业务与动态回调测试，DateTime、Mint、JSON 数字转换、两个 Go 字节原语的边界用例和参考结果。C 实现位于 `evidence/round3/simd/`。
- `scripts/`：Android SDK 构建、离线测试、源码打包和本地合成服务等工具。
- `reverse/`：各阶段自写提取/分析工具、业务协议说明和缺口报告。重新执行分析通常需要另行提供原 APK、反汇编结果或参考 SDK。
- `PUBLICATION.json`：公开副本的整理范围和历史资料说明。

主工程包名为 `com.re.xcs.rebuild`，包含 18 个主 Java 源文件及 2 个 Android 运行检查类；minSdk 26、targetSdk 28、compileSdk 35。

## 编译

准备 macOS / Linux 的 POSIX shell、Python 3.9 或更高版本、JDK 17 或更高版本、OpenSSL，以及 Android SDK 的 `platforms;android-35` 和兼容的 Build Tools（本次实际使用 `37.0.0`）。设置本机路径，例如：

```sh
export JAVA_HOME="/path/to/jdk"
export ANDROID_SDK_ROOT="/path/to/android-sdk"
python3 scripts/build_source.py
```

输出为 `dist/xcs-source-rebuild-debug.apk`，构建报告为 `dist/source-build.json`。构建会在本地生成开发 RSA 密钥和调试签名；密钥与构建产物均被 Git 忽略。克隆无需原 APK 即可构建当前 Java 工程。第一次准备 Gradle 依赖需要网络，也可使用：

```sh
./gradlew --no-daemon :app:assembleDebug
```

Gradle 输出为 `app/build/outputs/apk/debug/app-debug.apk`。项目使用 Gradle 8.13 / Android Gradle Plugin 8.11.1。

## 离线验证与模拟器

```sh
python3 scripts/verify_host.py
adb install -r dist/xcs-source-rebuild-debug.apk
adb shell am start -n com.re.xcs.rebuild/.MainActivity
```

`verify_host.py` 实际运行九套 host 测试，覆盖业务、设置、动态回调、模型、本轮集成、Mint、DateTime、SIMD 和 JSON 数字转换。SIMD 的 C 后端检查需要 C 编译器；本次在 macOS ARM64 上实际验证 NEON 与标量两种后端。参考数据回放、原机器码片段实验、重建 App 的运行验证分别记录，不能互相替代。

可用本地合成服务检查登录/WS 链路：

```sh
python3 -m pip install cryptography Pillow
python3 scripts/fixture_server.py
```

服务仅绑定本机 HTTP `127.0.0.1:8081` 和 WS `127.0.0.1:18889`；合成账号为 `fixture-user` / `fixture-password`。模拟器可用 `adb reverse tcp:8081 tcp:8081` 和 `adb reverse tcp:18889 tcp:18889` 转发到电脑。具体消息和测试入口见脚本及 `evidence/transport_contract.json`。

根目录构建所生成的开发密钥只适配本地合成数据。全量工作区归档按用户明确确认保留原有密钥及文件内已有的服务信息和凭据；根目录测试仍使用本地合成对端。

## 已知限制与历史证据

完整原 Flutter 布局、全部动态接收者、完整 Go/Rust 运行时、部分未知 `msg_type`、部分 WiFi/配置边界、OTA 与若干取消/并发时序仍未闭合；生产设备控制和上传没有完整验收。两个 SIMD 函数提供可编译语义实现，并不表示获得原作者源码。详细限制保留在 `重建工程说明.txt` 与缺口清单中。

`重建工程说明.txt` 和原 `evidence/` 报告描述本地历史交付，含当时的 APK/源码哈希；首版可直接浏览的源码区移除了密钥、日志、截图，并将部分本机路径脱敏为 `<LOCAL_APP>`。旧报告中的通过结论不自动适用于该源码区，当前公开构建和测试结果以 `PUBLIC_VALIDATION.json` 为准。首版源码区未纳入历史 `dist/` 产物及外部分析输入；完整文件已收入 `full-workspace/` 快照。

首版直接可浏览的源码区经过整理；后续补充的 `full-workspace/` 全量归档包含所有当时存在的 APP 文件，没有过滤原 APK、原 SO、DEX、密钥、产物或原始字符串转储。已有图片、音频、参考代码和构建工具保留其来源及原有权利；本仓库没有声明获得原应用完整源码的所有权，见 `NOTICE.md`。
