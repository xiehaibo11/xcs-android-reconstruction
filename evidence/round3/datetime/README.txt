第三轮 DateTime：Devices.create_time 与动态内容格式化

这里交付的是可执行 Java 功能重建 DartDateTime.java，未恢复原始应用 Dart 源码。
原调用链已追踪：Devices.fromJson 的 0x490328 调用 DateTime.parse(0x491264)，
Devices.toJson 的 0x459f80 调用 toIso8601String(0x45a9dc)。日期类型检查和解析
发生在 version.toDouble(0x490620) 之前；原错误优先级不能通过先验证全部字段再
统一转换来替代。Message 的动态 selector 对 DateTime CID4688 选择独立的
DateTime.toString(0x5715ac)，因此 ISO 输出和消息显示文本使用两个不同入口。

已经实际实现

- 按原对象池 PP+0x10578 的正则接受日期字符串，不进行 trim。年为可选正负号的
  4～6 位；月、日、小时等按原正则位数；T 或空格；Z/z 或数值时区；小数支持点/逗号。
- 月、日、小时、分钟和秒溢出会归一化；例如 2020-01-42 -> 2020-02-11。
  秒60按进位处理，不作为闰秒保存。小数秒只取前6位，不足补0，超过直接截断。
- 明示时区转换为 UTC；无时区按本地时区解释，即使本地是 UTC 也保留 isUtc=false。
  原两小时探测的夏令时解决次序已移植：重复时刻取较早实例，跳空取先前偏移对应时刻。
- 超出有符号32位秒数范围的本地偏移查询先换算为2008～2035年的等价日历年份，
  再调用系统时区提供者。没有直接采用 Java atZone 的默认策略。
- 原 ARM64 的64位 MUL/ADD 会溢出回绕，Java long 保留相同行为；六位超远年份
  并非一律拒绝。普通最终范围是 epoch 微秒 ±8640000000000000000。
- 负微秒向下换算毫秒：-1us -> -1ms。构造期间验证 microsecond 会建立字段缓存，
  后续格式化使用缓存；更改系统默认时区不会重解释已经构造的日期字段。
- ISO 格式使用 T；[-9999,9999]用四位年，其他年份用有符号至少六位。
  toString 使用空格；扩展正年不加“+”，例如10000而非+010000。
  毫秒始终三位；仅在微秒非0时再附加三位。只有 UTC 有末尾 Z。
- 普通格式/范围错误保留 FormatException 两种 reason。还补齐了最小64位整数
  特例：-290308-12-21T19:59:05.224192Z 会触发原构造链 RangeError；相同无后缀
  输入在洛杉矶时区触发原 native 秒数范围 ArgumentError。这些不是静默默认日期。

公共 API

DartDateTime.parse(String) 使用当前 TimeZone.getDefault()。
parse(String, TimeZone) 允许测试注入本地时区；显式字符串时区仍优先。
对象提供 toIso8601String()、toString()、isUtc()、microsecondsSinceEpoch()、
millisecondsSinceEpoch() 和拆分日期字段 getter。Models 与 DartConversions 的
业务接入由主工程维护，本文件夹的测试只验证独立 DateTime 实现。

实际验证及其区别

1. 原静态指令复核：contracts.json 核对2个原业务方法完整证据体、31个 SDK 方法
   证据体，共4042条 ARM64 指令字。business_proofs/SDK_proofs 给出原 ELF 位置和哈希。
   共享方法与 DateTime 内部 helper 根据原 snapshot 元数据定位，没有凭函数名猜目标。
2. 原机器码有界执行：machine_execution.json 记录 Unicorn 执行原 libapp.so 的
   _dayFromYear、_weekDay、_equivalentYear，以及 _brokenDownDateToValue 的 UTC
   算术路径，共24211次比较通过：18015次年份 helper，6196组规范化组件，其中197组
   被范围判定拒绝。执行观察到234条不同指令地址。Dart栈、线程、常量池/日期数组与
   Mint分配边界已明确建模；没有执行原完整正则解析器、字符串格式化、Android或App。
3. 官方参考运行：reference_verification.json 记录官方 Dart SDK 3.5.2 macos_arm64
   实际运行 reference_oracle.dart，与 Java 对照6204个输入×6个时区=37224次，0差异。
   范围包含固定种子6000个随机日期、输入格式、溢出/分数、范围端点、64位最小值及
   夏令时边界。六个时区为 UTC、America/Los_Angeles、Asia/Shanghai、Europe/Berlin、
   Australia/Lord_Howe、Pacific/Apia。参考运行不是执行原 APK 的 DateTime 方法。
4. 便携回放：62条专门边界断言与上述37224条已保存参考输出均能在源码ZIP中离线
   复跑，不需要 Dart SDK、原 APK、Android SDK、外部 analysis 目录或业务服务器。

从 reconstruction 目录执行：

  sh evidence/round3/datetime/run_tests.sh

脚本优先 JAVA_HOME，再使用本机 Android Studio JBR，其他环境回退 PATH 中的JDK。
编译目标为 Java8；脚本需要支持 --release 的JDK9或以上。输出应分别显示
“PASS 62 DateTime assertions”和“PASS 37224 saved Dart 3.5.2 reference comparisons”。
reference-fixtures.zip 包含Base64输入和六个区的原参考输出，manifest记录内部哈希；
reference_fixture_manifest.json 另记录 ZIP 哈希。SDK二进制不放入源码ZIP。
若将来本机/JDK时区库改变导致回放不一致，测试会明确失败，不屏蔽或改写参考结果。

参考来源与许可

reference_sources/date_time.dart 与 date_patch.dart 是 Dart 3.5.2 官方版本源码，
reference_sources/date.cc 来自本地同版本 VM。它们用于参考和核验，未加入 Java
编译，也不是从本APK恢复的应用源码。Java日期算法依据这些BSD许可的Dart规则
进行移植；版权声明和BSD条款见 DART_LICENSE.txt。官方获取地址和文件哈希在
contracts.json 中。完整机器码提取/执行与重新生成参考输出的脚本保留于
APP/analysis/reconstruction_round3/datetime；便携回放不依赖该目录。

仍然有界

系统时区数据来自所在OS/JDK；同一区名但不同历史 tzdata 版本仍可能有偏差，不能
声称全部平台、全部历史时区等价。Java保留相关错误类别、reason及原异常发生位置，
不复刻Dart异常对象布局、完整字符串或栈。DateTime其余API、原Flutter控件树、
完整应用原源码及全部业务动态等价不因这项实现而恢复。没有修改冻结完整性基线。
