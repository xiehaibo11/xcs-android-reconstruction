
from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import json
ROOT=_public_app_root()/'reconstruction'
def read(p):return json.loads((ROOT/p).read_text())
build=read('dist/source-build.json');run=read('evidence/runtime/verification.json');live=read('evidence/round3/live/android-verification.json')
assert run['status']=='PASS' and live['status']=='PASS_READ_ONLY_LIVE_LOGIN'
text=f'''XCS 重建工程交付说明
当前状态：第三轮，2026-10-15

本轮已完成的交付

本目录是可编辑、可编译的 Java Android 重建工程，共 {build['source_files']} 个 Java 编译输入
（18 个主源码、2 个运行检查类）。SDK 和 Gradle 两种构建均已通过。同一交付 APK
通过 {len(run['assertions'])} 项 Android 实际运行检查及 {len(live['checks'])} 项真实后台只读检查。
这是依据原始二进制证据新写的实现；原始 Dart、Rust、Go 源码没有完整恢复，
原 Flutter 界面和全部业务行为也没有全部证明等价。未知分支仍有明确边界，
没有把伪代码、反编译器诊断输出或保留二进制计作已经恢复的原始源码。

可安装 APK：dist/xcs-source-rebuild-debug.apk
源码压缩包：dist/xcs-reconstruction-source.zip
完整构建输入与哈希：dist/source-build.json
最终交付验证：dist/delivery-verification.json
APK SHA-256：{build['apk_sha256']}
包名：com.re.xcs.rebuild；minSdk 26、targetSdk 28、compileSdk 35；使用调试签名。

重点补齐的逻辑

1. DateTime
   Devices.create_time 现保存为真正的 DartDateTime 对象，序列化调用 toIso8601String；
   原字段检查/日期解析发生在 version.toDouble 之前，错误先后顺序已接入。
   Message 内容为 DateTime 时调用原独立 selector 对应的 toString，输出空格分隔日期时间，
   与 ISO 的 T 格式区分。包含本地/UTC、显式偏移、年月日时分秒溢出、微秒截断、
   扩展年份、Dart 64位溢出行为、负时间及夏令时处理。
   最小64位特殊值导致的 RangeError/ArgumentError 路径与一般 FormatException 分列。
   62 条边界断言和 37,224 次官方 Dart 3.5.2 参考对照通过（6个时区）。
   另有 24,211 次原 ARM64 算术片段比较；模拟器建模了 VM 内存/分配边界，
   并非原 APK 全部 DateTime 解析/格式化入口的执行证明。
   证据：evidence/round3/datetime/

2. Mint/Smi 与动态数值
   原 CID60 经 Object_toString 最终调用 Mint::ToCString，输出 signed64 十进制；
   原 CID59 与 CID60 的分界按此压缩指针 snapshot 保留。完整 Long 范围的字符串、
   toDouble 舍入及 Message 中的嵌套转换已接入，超2^53不伪造精确浮点整数。
   52 条边界断言和 20,856 次匹配 VM 参考对照通过。
   VM oracle加载原snapshot后执行重新编译的VM参考方法，不是原libflutter native执行。
   证据：evidence/round3/mint/

3. HTTP/WS 的 JSON 数字入口
   signed64 内整数字面量保持整数，超范围转 Double；指数溢出保留 Infinity、
   下溢及 signed zero。保留 Dart3.5.2 的末尾token与分隔符路径差异及大指数分支。
   29 条边界断言和 52,778 条官方SDK参考用例通过，并分别检查 parse/parseStrict。
   编码端继续拒绝非有限数值；这不是完整 JSON codec 已恢复的结论。
   证据：evidence/round3/numeric_json/

4. 两个 SIMD 共享函数
   countbytebody (0x5ae90) 与 indexbytebody (0x5b310) 已提供真实可编译的 C/NEON、
   标量以及 Java 语义实现；Java 类编入 APK，并在 Android 实际执行。
   16,160 输入，原ARM64函数执行32,320次；C结果检查96,960次，Java结果检查
   64,640次加36个边界，另有1,218个原指令内存边界与26,156个ASan/UBSan检查。
   原指令100/100已在限定片段测试中覆盖，不等于整个Go运行时覆盖。
   原index读取完整32字节对齐块；安全Java/C接口限制在逻辑切片内，填充C接口单列。
   原Ghidra两本体自动反编译仍有2个错误，诊断改写能生成C但没有作为实现交付。
   没有证实这些函数的新业务调用点，因此未擅自替换RSA登录调用。它们的原作者源码
   恢复数仍为0；已完成的是限定范围可执行语义重建。
   C源码与说明：evidence/round3/simd/go_byte_primitives.c、README.txt
   Java：app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java

编译与复测

在本目录执行：
   python3 scripts/build_source.py
   ./gradlew --offline --no-daemon :app:assembleDebug
   python3 scripts/verify_host.py

SDK脚本使用 JDK、Android SDK android-35/build-tools36.0.0；支持 JAVA_HOME 和
ANDROID_SDK_ROOT。本机JBR位于Android Studio应用目录，SDK位于 ~/Library/Android/sdk。
Gradle8.13/AGP8.11.1依赖已在本机缓存；别的机器须安装SDK/JDK并准备相应依赖。
Gradle产物位于 app/build/outputs/apk/debug；本次实际安装验证的是 dist/ 下SDK构建产物。

verify_host.py执行九组便携测试：64业务、102设置、124回调、38模型、33本轮集成，
以及Mint、DateTime、JSON数值和SIMD的边界/录制结果回放。
当前结果及所有输入哈希：evidence/round3/integration/host-verification.json。
上一轮的20,100浮点格式参考样本及Go8项原始证据继续保留为历史记录，未重写为本轮新执行。

14项本机TCP WebSocket回归通过，报告 evidence/transport/network_verification.json。
本轮Android API35检查35项，包含实际Activity登录、日期转换、Mint/JSON数值、字节原语、
WS认证/心跳、101图像解码缓存与模拟结果上传、预览结束失败/晚到WS102/重新进入、
编辑取消、设置五字段请求、WiFi扫描选择保存。使用本机合成对端，不是生产设备验收。
报告及截图：evidence/runtime/。

真实后台只读链路通过7项：登录、JWT/RSA配置解密、设备version、设备日期解析/ISO往返、
牌配置、在线配置与设备状态、WS认证。读取4台设备、50项牌配置；设备模型unresolved为空。
仅使用六条限定HTTP路由和WS认证，没有执行生产控制、预览、参数写入或结果上传。
报告：evidence/round3/live/android-verification.json；未保存凭据及原始响应。

源码ZIP的独立性

源码包包含Java源码、C语义实现、保留assets、Gradle配置、构建/测试脚本与evidence。
所有新增便携测试可离线回放录制参考结果，不要求原APK、原VM源码、Unicorn或Dart SDK。
原始参考生成/原指令执行工具在完整APP目录下 analysis/reconstruction_round3/，
它们不等于便携回放；工具及大型外部SDK不会全部打入源码ZIP。

   python3 scripts/package_source.py
   python3 scripts/verify_source_package.py

第二条会在独立临时目录解压源码，确认不存在原APK/apktool项目，实际编译/签名并
复跑九组测试，再逐字节比较DEX及assets与本轮已运行APK。结果与ZIP哈希分别记录在
 dist/standalone-build-verification.json 与 dist/source-package.json。
保留assets含图像/PEM等，由 evidence/retained_assets.json 绑定哈希；它们不是恢复的源码。
历史证据部分使用本机绝对路径，独立包不包含外部 APP/analysis 全树，迁移后可能无法打开。

仍未恢复或仍有限制

- 原始Dart/Rust/Go完整工程、原注释/变量/项目结构、树摇/内联丢失方法、原签名。
- 冻结审计的12个大类仍open；612个导出业务方法、225局部关联/387无关联基线不改，
  新增局部证据不能换算成所有方法完成。JADX告警、未完成插件与未知动态分支仍待处理。
- DateTime依赖宿主时区数据库，跨Android/宿主tzdata版本不能宣称全部历史/未来偏移等价；
  新类覆盖观察到的parse/格式化路径，没有补整个DateTime API及异常对象实现。
- 任意自定义动态接收者、BigInt、循环容器与完整noSuchMethod仍未恢复。
  Message reader为记录unresolved而提前做能力检查；原fromJson只存内容，故可变容器
  先循环后修复等异常时序仍有差别。MjConfig原factory未恢复，重建适配器仍明确标注。
- JSON有限Double编码仍采用Java拼写，数值等价时文本也可能与Dart不同；完整非数字
  codec、错误文本、流式/分块API没有因数字解析补齐而完成。
- 两SIMD原体自动反编译错误、Rust两项类型传播警告、完整Go运行时/调度/信号/并发、
  其他ABI全部语义、原生跳转表和未归属区间仍open。安全切片API的参数错误是重建防护，
  不宣称复现原汇编非法指针故障。
- WiFi异常比较器的完整排序结果、异常恢复、非字符串data和部分设置整数输入仍未闭合。
- inlet_pwd.conf的完整读取/解锁用途、msg117第1段及发送方schema、未知msg_type仍未确认。
- 原Flutter完整布局/渲染、OTA安装、图片重编码旋转、Cookie跨进程持久化、Dio全部取消/
  超时/重定向以及原Rust完整并发语义仍open。
- 生产设备控制/上传、真实断线重连/认证失败全部时序、原程序完整端到端等价尚未验收。

历史交付与冻结证据

dist/history/round2/保留上一轮APK、源码ZIP与交付哈希，防止用新文件覆盖历史证明。
evidence/README.txt区分当前报告和历史报告；evidence/gap_progress.json逐项保留基线，
附当前证据；evidence/business/source_map.json对应实际实现。

另有 dist/original-bytecode-rebuild.apk：apktool重装Smali/资源，原13个.so及115个assets
逐字节保留。此前5133类/28975定义方法的规范化Smali往返及298资源ID检查通过。
该包仅在上一轮验证隔离离线启动，未做完整业务验收；原生部分仍是原二进制，
它不是原始源码工程，本轮也没有把它当作Java重建逻辑的执行替身。
其构建脚本 scripts/rebuild_original_bytecode.py 仍需完整APP的外部原APK/apktool输入。
'''
(ROOT/'重建工程说明.txt').write_text(text)
print('Wrote current README; APK',build['apk_sha256'])
