第三轮：Mint/Smi 的动态整数转换

结论与边界
已补齐原 Message.msg_content 中 native Dart int（Smi 与 Mint）的十进制 toString，以及整数 toDouble 的有界 Java 实现。原始类文本没有恢复；本目录不宣称执行了原 APK 的 libflutter 本机入口，也不宣称完整 Object.toString 或所有动态类型已经完成。

为什么 Mint 走 Object.toString 仍是数字文本
原 Message.toJson 的 0x52a330 使用 GDT[cid+0x6d49]。读取同一个原 snapshot 的 CID60，结果为 0x580b30，原 Function.native_name 明确为 Object_toString。这个入口的 native 名称是本轮新增读取证据，不是凭 canonical 标签猜测。
Dart 3.5.2 的 Object_toString 创建 Instance::CheckedHandle 后调用 instance.ToCString()。Instance handle 保留具体类的虚方法；Mint::ToCString 实现使用带符号64位 Pd64 格式，所以返回 -9223372036854775808 到 9223372036854775807 的十进制文本。不能把这里直接解释为通用 Instance of ...。
本轮匹配 VM 参考运行对 20,462 个 Mint 实例实测了 Instance::ToCString，全部为相应十进制字符串。String、AbstractType 和其他普通 Instance 的分支不由本 helper 承担。

整数 toDouble
原 _IntegerImplementation.toDouble(0x6f791c) 调用 _Double.fromInteger(0x2ebc94)。后者的原 Function.native_name 为 Double_doubleFromInteger。Smi 的机器码快速路径先提取有符号31位 payload，执行 SCVTF；Mint 进入 native fallback。
匹配 VM 源码中 Double_doubleFromInteger 调用 Integer::AsDoubleValue；Smi/Mint 均把其带符号整数值转换为 double。Java 实现保留这个舍入：9007199254740993 转为9007199254740992对应的double，Long.MAX_VALUE 转为2^63对应的double，而不是声称所有大整数精确保留。

表示范围与 ABI
原 snapshot 和匹配构建使用 compressed pointers。Smi 范围为 [-1073741824,1073741823]，超出后分配 Mint；Mint payload 仍为完整带符号64位。
这项范围仅描述所检查的 ARM64 compressed snapshot。不能将“64位平台”误写为必然63位Smi，也不能把压缩指针理解成Mint值截成32位。
DartIntegers 中 Byte/Short/Integer/Long 是重建适配器。Java Integer 超出Smi范围时仍按同一个 native Dart int 的含义处理。拒绝 null/String/bool/Float/Double/BigInteger/BigDecimal/AtomicLong 等接收者；Double仍由上层DartConversions自己的double分支处理。

实现与运行
app/src/main/java/com/re/xcs/rebuild/core/DartIntegers.java
- isInteger(Object)：仅接受4种标准整数包装类型。
- toDartString(Object)：完整带符号64位十进制，包括最小负数。
- toDouble(Object)：带舍入的binary64转换。
- snapshotClassId(long)：仅返回所检查snapshot的59/60表示分界，用于证据测试。
根线程负责把上述API接入DartConversions/Models，相关整体构建与Android验证见交付总报告。本目录只保证其独立源文件和测试哈希。

验证
运行本目录 run_tests.sh：离线使用JDK9+的 --release8 编译，52个边界和明确拒绝断言、20,856个参考差分用例通过，其中Smi394、Mint20,462；每个参考用例同时比较CID、十进制文本和double原始64位位型。
reference.tsv 由本地匹配Dart VM3.5.2编译库产生，先加载原 libapp.so snapshot，再直接运行 Integer::New、Instance::ToCString、Integer::AsDoubleValue。其本机代码是重编译的参考VM，不是原APK native引擎；此区分记录在verification.json/contracts.json中。
样本为固定种子35260的20,000个signed64随机值，以及0、±1、2的幂及相邻值、Smi边界、2^53舍入边界和signed64极值等856个非重复边界值。不是遍历所有2^64输入的证明。
同时从原ELF导出了Message.toJson、Object.toString、Integer.toDouble、Double.fromInteger四个方法完整选定范围，共151条ARM64指令，保留地址、字节、SHA256与源ELF哈希。

证据文件
contracts.json：原绑定、机器码范围、VM源码片段、实现边界、测试与文件哈希。
verification.json：独立测试结果及对应实现/测试/参考数据哈希。
reference.tsv：原snapshot元数据与匹配VM参考输出，供源码包独立离线回放。
*.raw.txt：直接来自原libapp.so的原始ARM64字节/反汇编。
*.L*.txt：匹配VM源码的有限片段及行号，完整原参考文件哈希见contracts。
分析侧 analysis/reconstruction_round3/mint/verify_mint.py 可在本完整逆向工作区重新构建、读取snapshot、运行参考并生成合同。该工具需要已有blutter依赖，源码包便携回放不需要它们。

仍未恢复
BigInt的数值转换/格式化、任意自定义动态receiver、完整noSuchMethod/异常对象等价、完整Object_toString、多架构全部运行时和原始Dart项目源码仍没有因此恢复。
DateTime不是Object_toString路径：原CID4688的同一GDT selector有独立DateTime.toString入口0x5715ac；必须接入本轮单独的DateTime实现，不能以本整数helper替代。
