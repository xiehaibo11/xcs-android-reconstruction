本轮仅补齐两个共享体：countbytebody ELF 0x5ae90、indexbytebody ELF 0x5b310。
交付的是实际可编译的行为重建实现，不是原作者源码；未建立它们与登录/RSA业务的真实调用关系。

直接运行便携测试

sh evidence/round3/simd/run_tests.sh

脚本可从任意工作目录运行。需要 JDK；若可找到 cc，会同时测试 C 的本机后端和强制标量后端。
不需要 Android SDK、Gradle、Python、Unicorn、原始 APK、网络或凭据。
original_arm64_cases.bin.gz 包含原 ARM64 共享体实际执行产生的结果，数据为纯合成字节。
文件为 gzip 包装的二进制：8字节 XCSSIMD3、BE32用例数；每例 BE32(size,offset,length,target)，
随后 size 字节输入，再后 BE64(count,index)。index=-1 用 64 位补码。输入保留匹配的前后填充。
run_tests.sh 将夹具解压到临时目录，在退出时清理临时编译产物。

Java 接入 API

com.re.xcs.rebuild.core.GoBytePrimitives.count(byte[] data,int offset,int length,byte target)
com.re.xcs.rebuild.core.GoBytePrimitives.indexOf(byte[] data,int offset,int length,byte target)
两个函数均另有 int target 重载；int 值须在 0..255 范围内，byte 按其无符号位模式比较。
count 返回命中字节数；indexOf 返回切片相对的首个命中字节位置，未找到返回 -1。
null,0,0 允许为 Go nil 空切片；其余 null 使用抛 NullPointerException。
负偏移、负长度、超界和 offset+length 溢出风险抛 IndexOutOfBoundsException。
int target 不在 0..255 时抛 IllegalArgumentException。
这些错误类型属于重建 API 的显式约定，不冒充原 Go 汇编中的异常处理。
Java 数组长度/索引由 int 限定；原 Go ARM64 长度使用机器字，不能据此声称二者完整 ABI 相等。
Java 使用普通字节数组读取，没有 SIMD 指令或对逻辑范围外内存的读取。

C 接入 API

go_byte_primitives.h/.c 可以独立编译。xcs_count_slice、xcs_index_slice 接收
storage、storage_size、offset、length、unsigned target、result 指针。
xcs_index_padded_slice 另外复现原查找算法的对齐块读取方式，要求 storage 完整包含有关对齐块；
缺少前后填充返回 XCS_NEEDS_PADDING。安全版 xcs_index_slice 对不足32字节的首尾使用标量读取。
调用者必须保证非空 storage 指针真实指向 storage_size 字节的可读对象，result 指针真实可写。
函数可验证数值范围，不能在可移植 C 中证明任意地址实际属于可读/可写对象。
length 限定至 INT64_MAX；空 NULL 仅允许 size=offset=length=0。
返回 XCS_OK、XCS_INVALID_ARGUMENT、XCS_INVALID_RANGE 或 XCS_NEEDS_PADDING；不修改业务状态。
小端 ARM64 可使用 NEON；其他情况或 -DXCS_FORCE_SCALAR 使用标量后端。
实际编译/执行平台为 macOS ARM64 小端；其他平台有可移植代码路径，但本轮没有硬件运行证据。

原机器码的完整本体语义

两个共享体使用 x0=数据指针、x1=已零扩展目标字节、x2=长度、x8=8字节结果地址。
真实上层 ABI0 wrapper 使用 LDRB 装入目标字节，因此 x1 在 0..255 内。
共享体自身不检查无效长度、非法地址或目标超范围，结果地址即使在空输入时也必须有效。

countbytebody：
0x5ae90..0x5aea0：计数归零，长度为零直接写结果；短于32字节转标量路径。
0x5aea0..0x5aec8：若地址未对齐，先逐字节读取到下一个32字节边界。
0x5aec8..0x5af20：剩余完整32字节块，每次读取两个16字节向量；相等比较产生0xff/0；
再 AND 1，逐对 ADDP，UADDLV 求和（每块0..32），累积到64位计数。
0x5af20..0x5af3c：标量处理尾部，写入结果并返回。
计数函数访问的输入地址集合恰好等于逻辑输入范围，不需要头尾额外可读字节。
末尾0x5af3c的零字只是 pclntab 区间内的对齐填充，不计入可执行本体43条指令。

indexbytebody：
0x5b310..0x5b338：长度为零返回-1；保存原起点，向下对齐32字节，广播目标字节与权重0x40100401。
0x5b338..0x5b374：读取未对齐首块；两次ADDP把比较结果变成64位位图，每个输入字节占两位；
清除逻辑起点之前的位，必要时直接进入尾部掩码。
0x5b374..0x5b398：循环读取完整对齐块，先以比较结果的OR/成对64位加法快速判定是否存在命中。
0x5b398..0x5b3c8：构造有位置权重的位图；长度不足完整块时清除逻辑结尾后的位。
0x5b3c8..0x5b3f4：无命中返回-1；否则RBIT、CLZ取得最低有效匹配位，除以2形成块内位置，
加块起点再减原始输入起点，写出切片相对位置并返回。本体共57条指令。
非空输入可能向前/向后额外读取至多31字节；无命中时读取范围恰好为覆盖输入的32字节对齐块。
早命中会提前结束，所以“整个对齐覆盖范围”是一般上界，并非每次都全部访问。
逻辑范围外的匹配通过位掩码排除；这不消除实际的范围外读取。
测试在单一映射页的两侧设置未映射页，合法切片通过；不能把这种页边界通过推广成任意堆对象安全。

差分与错误边界证据

verification.json 为本轮汇总；differential_verification.json 保存详细记录、哈希与逐指令覆盖。
16,160 个输入；原 ARM64 共享体执行32,320次，覆盖全部100条本体指令。
编译 C 两个后端共96,960个结果检查；Java 两种重载共64,640个结果检查，另36个错误/空输入边界。
原指令额外1,218个内存/错误/页边界检查；其中1,152个用例逐次记录并核对实际读取地址集合。
C 两个后端分别通过13,078个 ASan/UBSan 与保护页检查。
覆盖32种未对齐、全部256个目标字节与32种对齐的组合、全部32个SIMD命中位置、随机输入、
32字节循环的首尾、0/1/2/3/7/15/16/17/30/31/32/33/47/63/64/65/95/96/97/127/128/129/
255/256/257/511/512/513/1023/1024/1025/4095/4096/4097长度。
输出 oracle 为独立 Python bytes.count/bytes.find，并与原机器码返回值比较；没有共用同一掩码算法。

Ghidra 仍存在的两个原体错误

原始两个本体依然报 Unable to find unique hash for varnode。原体反编译失败数量仍是2。
源码中的报错位于 Funcdata::buildDynamicSymbol，表示数据流 varnode 无法取得唯一动态符号哈希。
本机 DynamicHash::uniqueHash 使用最多8项冲突编码；本轮未记录到实际碰撞个数，不据此推断碰撞数。
只读诊断逐个把 SIMD 指令替换成 NOP 后复测，再恢复原字节；这是改变语义的消减实验。
count 的循环 LD1(0x5aeec)、ADDP(0x5af04) 或 UADDLV(0x5af08) 被消减时可输出C；
index 的循环 LD1(0x5b374) 被消减时可输出C；多数其他单指令消减仍失败。
另将三处 LD1 双向量加载临时标记为相同向量/地址/步长的 LDP，两个分析副本均可输出诊断C。
这是对分析副本的指令改写；没有改变 APK/原始库，也没有宣布原体已正常反编译。
该 LDP 诊断没有作为交付实现使用，也没有用它替换差分测试中的任何原始指令。
所有消减/改写都在只读项目的回滚事务中运行。ghidra/ 内的 C/XML 仅供诊断，不可当作已恢复源码。
真实可编译并测试的实现是手写 go_byte_primitives.c 与 GoBytePrimitives.java。

进一步复核原机器码

分析目录 differential_test.py 可在本机已有 pyelftools、Unicorn、clang 和 JDK 下重跑完整验证。
它读取 APP/unpacked/lib/arm64-v8a/librsa_bridge.so，映射 ELF 片段，不执行 Android、Go runtime或系统调用。
Unicorn 当前 macOS 环境在受限沙箱内可能于宿主初始化触发SIGILL；原片段测试使用批准后的离线执行。
便携 run_tests.sh 仅重放已录制结果，不假称在源码ZIP中重新执行了原机器码。
