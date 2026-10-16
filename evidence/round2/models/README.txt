第二轮：Devices.version 与 Message.msg_content 模型转换

本目录记录可执行 Java 功能重建的有界合同，不宣称恢复了 Dart 原始源码。contracts.json 是静态证据和实现范围；verification.json 由主线程测试脚本维护，本证据整理没有改写它。

Devices.version
原 Devices.fromJson 入口 0x4901f0。在 0x4905f4..0x490604 取 JSON[version]，紧接着把该值放入 receiver slot，在 0x490614..0x490620 调用 PP0x10840 对应的 UnlinkedCall。
原 snapshot 的 target_name 读取结果是 dyn:toDouble。这比凭反编译占位名猜测具体方法更精确。该调用前没有 null 默认值、数字字符串解析或跳过分支。
返回值保存后在 0x491128..0x491130 提取 Double payload，写入 Devices.field37 的未装箱 double。
当前 Java 接受整数类型与 Double，返回对应 double；拒绝 null、String、bool、自定义 receiver。整数转换属于数值重建，极大整数存在浮点舍入，不能把“数字可转”写成“数值不变”。
原 snapshot 还能确认 Double.toDouble 的 0x6f78fc 是 ldr x0,[SP];ret，直接返回 receiver。所有 IC receiver/noSuchMethod 分支并未逐一恢复。

Message.toJson
入口 0x52a2a4：msg_type 直接复制；0x52a308 检查 msg_content 是否 null。为空时跳过动态调用并写实际 null，不是文本"null"。
非空时 0x52a330 使用 GDT[cid+0x6d49]。原 snapshot 解析确认以下 receiver：
- CID59 Smi：0x580434，Smi.toString。
- CID60 Mint：0x580b30，Object.toString。不能因为另一个整数类型是十进制输出就直接外推此路径；当前明确保留未知并拒绝大整数内容。
- CID61 Double：0x580114，Double.toString。
- CID62 bool：0x5800fc，返回池中的true/false字符串。
- CID93/94 String：共同入口0x6f79a8，真实8字节为 ldr x0,[SP];ret，返回原字符串。pretty-printer 的 RestorationBucket 闭包名称是共享代码的规范标签，不能理解成调用恢复桶逻辑。
- CID89/90/91 List：0x57fb60，ListBase.toString。
- CID85/86 Map：0x57fbfc，MapMixin.toString。
当前 String、bool、压缩 Smi 范围整数、Double、无环 List/Map 可执行。List/Map 使用 Dart 显示格式，例如 [a, true, null, 2] 和 {x: [1, 2]}，不是 JSON 编码。

验证范围
静态合同核对了3个完整导出业务方法证据体及3段框架入口机器码，共1811条 ARM64 指令，均与原 ELF 字节及冻结方法哈希一致。Message.toJson 是1个新增有界语义关联；整方法完成声明仍为0。
Java 模型测试38个断言通过。run_tests.sh 只需 JDK9 或更新版本，用 --release8 编译4个纯 Java core 文件及测试，不需要原 APK、Android SDK、C++工具链或 Dart源码；不访问网络、不覆盖 verification.json。
已有 verification.json 中，Double 字符串转换20100个样本与本地 Dart VM3.5.2 double-conversion 参考实现逐项一致：20000个固定种子随机位型，100个边界/相邻位型。
参考设置来自 Dart3.5.2 DoubleToCString：ToShortest、十进制指数区间[-6,21)、e、正指数加号、整数double附 .0、Infinity/NaN、保留负零。
这项对照运行本地 C++ 参考库与 Java重建，未执行原 APK 的 Double 方法；它是抽样差分证据，不能证明全部IEEE754位型或整个 App行为等价。Double格式化验证不等于toDouble数值转换验证。

仍未恢复
1. Devices.create_time：原路径 DateTime.parse(0x491264) 与 toIso8601String(0x45a9dc) 的完整语义，含时区、溢出、日期范围和小数秒。当前保留原字符串并声明 unresolved，Devices.Record.toJson 会拒绝伪造完成。原始无效日期的异常时序也没有通过保留字符串恢复。
2. Mint 的 msg_content.toString 可观察文本；不能用普通十进制字符串替换后宣称等价。这里不否认 Devices.version 的大整数数值转换，而是区分不同 selector。
3. 自定义动态 receiver、DateTime 作为 msg_content 的输出、循环容器及原 Dart 递归/截断行为。
4. Flutter/Dart 原始类文本、注释、布局、项目文件与未知业务逻辑。

文件
contracts.json：原始数据流、receiver表、实现边界、机器码复核、文件哈希。
methods/：三个业务方法完整证据体和原始字节反汇编；三个框架入口的选定片段。
ModelConversionTest.java / run_tests.sh：38断言的便携离线复跑入口。
build_contracts.py：静态合同复核生成器，需要本项目原证据、Python pyelftools与capstone，不属于运行38断言的依赖。
原始 metadata工具在 APP/analysis/reconstruction_round2/models/snapshot_model_targets.cpp；仅读取snapshot对象池和分发表，不调用目标Dart业务方法。
