第三轮：JSON 数字入口与 Mint/Double 衔接

已实现
JsonCodec.number 保留 native Dart signed64 整数类型。含2^53以上但不超signed64的整数仍是Long；-0是整数0。超过signed64的整数字面量回退为Double，不再提前抛“范围外”。小数或指数形式始终产生Double，保留负零、次正规数、向零下溢和正负Infinity。
JsonCodec.stringify 的非finite拒绝逻辑保持生效：NaN、Infinity、-Infinity在顶层或列表/Map内都不能编码为JSON数字。解码合法巨大数字得到Infinity与允许编码Infinity不是同一行为。
本轮没有把BigInteger当作原Mint，也没有将所有大数先转Double。DartIntegers已经接入的signed64精确路径可从真实JSON入口抵达。

原APK与参考证据
原snapshot中读取了parseNumber、finishChunkNumber、NumberBuffer.parseNum/parseDouble及_parseDouble的函数身份；_parseDouble(0x2edd6c)真实native_name为Double_parse。
5个原方法范围共897条ARM64指令已直接从原ELF导出、记录字节和SHA256。记录不等于声称每个SDK分支都穷尽执行。
原parseNumber 0x2ed7e8与0x190(400)比较指数；0x2ed804在token恰好结束时转入chunk路径；0x2ed858检查指数溢出标志。0x2ed85c..0x2ed938按mantissa、exponent sign和number sign写入零/负零/正负Infinity。原object pool再次读取确认PP0xbe8=0x7ff0000000000000、PP0xc90=0x8000000000000000、PP0xc98=0xfff0000000000000。
原0x2eda04..0x2edb40还有mantissa<2^53、指数范围±22的FDIV/FMUL快速路径。参考Dart3.5.2 convert_patch.dart对应代码片段与行号保留在本目录。
官方Dart3.5.2 macOS ARM64 SDK运行jsonDecode/jsonEncode产生reference.tsv。它是匹配版本的本机参考VM，不是原Android libflutter执行。

必须保留的上下文差别
Dart3.5.2对数值token恰好到达输入末尾与后面有空白/分隔符有两个执行路径。本轮有意识地保留它们，而不是全部替换成通用Double.parseDouble：
- 400个9后接e-401：独立顶层token得到0.1；尾随空格或放在列表/对象中得到0.0。
- 0.后接401个0再接1e401：独立顶层token得到0.1；尾随空格或放在列表/对象中得到Infinity。
原因是结束缓冲区路径重解析完整token，而已结束token的快速路径对指数>400先做shortcut，没有先合并全部小数位数。上述结果来自真实参考运行，原机器码中也存在对应分支。这些行为不应被以“更合理”或“数学上正确”为由悄悄修改。

验证
本目录run_tests.sh仅需JDK9+，以--release8离线编译JsonCodec.java和NumericJsonTest.java，读取已捕获的reference.tsv；不需要APK、Android SDK、Dart SDK、C++或网络。
29个直接边界/编码拒绝断言通过。52,778条参考差分行通过，分别检查parse和parseStrict两种入口：16,372整数、36,276 Double、130畸形输入；Double中含8,034条非finite结果。
用例来自162种明确边界token、固定种子3521303生成的13,000种随机token和34种畸形token；有效token分别覆盖输入末尾、尾随空白、列表、对象四种上下文。随机集包括signed64整数、超界19..120位整数、正负小数与±600范围指数；明确边界包含Smi、2^53、MIN/MAX±1、subnormal、最大finite附近、100位指数、400位mantissa和溢出上下文差异。
这不是遍历所有可能JSON输入的证明。

文件
contracts.json：行为合同、原机器码关联、native_name与object pool、参考来源、剩余边界、文件哈希。
verification.json：对应源码/测试/fixture哈希和实际测试计数。
reference.tsv：官方参考实测输入（UTF-8 Base64）及int文本或double64位hex，支持独立回放。
NumericJsonTest.java、run_tests.sh：便携Java验证。
*.raw.txt、snapshot_metadata.tsv：原二进制静态证据。
convert_patch.dart.L*.txt：有限官方源码片段。
DART_LICENSE.txt：Dart BSD许可。Java数字fast path基于该匹配版本已验证算法改写，不是声称找回原App源文件。
完整工作区的analysis/reconstruction_round3/numeric_json/verify_numeric_json.py可重建fixture和snapshot元数据；只复用已下载SDK，不联网。

明确剩余
整个JSON codec不宣称与原SDK完全等价。非数字Unicode/转义边界、资源与递归限制、流式chunk API、任意toJson接收者、错误类/文本/偏移等仍未全量恢复。parseStrict的重复键拒绝仍是此前声明的重建加固。
JsonCodec.stringify对finite Double仍使用Java Number.toString，数值相同的JSON可能采用与Dart不同的十进制/指数字面拼写。Message.msg_content经过DartConversions的文本转换是另一条已独立实现/测试的路径，不能用它证明整个JSON编码器文本一致。
原完整源码、所有架构/其他VM版本与整体App行为不因这些测试完成而变成已恢复。
