# 逆向分析工具与历史报告

此目录公开自写静态提取脚本、参考数据生成器、可执行重建验证工具和历史报告。原 APK、原始私钥、生产登录信息、签名密钥、第三方 SDK、机器码二进制、大规模自动反编译转储和本机运行目录未复制到这里。此目录不表示完整原始源码已经恢复，也不表示历史报告中的所有推断已实现为可运行代码。

| 目录 | 内容 |
| --- | --- |
| `scripts/` | 46 个原分析入口脚本，以及公开版本的路径配置辅助模块 |
| `round_tools/` | 三轮分析中 43 个小型自写工具和可编译 C、Java、C++、Dart 参考程序 |
| `reports/` | 10 份历史 TXT 报告与一份历史完整性审计台账 |
| `publication-manifest.json` | 原文件相对路径、原文件哈希和公开副本哈希 |

## 外部输入与配置

这些工具原先依赖一个已有的 `APP` 工作目录，其中包括 `input/`、`unpacked/`、`analysis/`、`ghidra/`、`tools/` 和 `reconstruction/` 等内容。公开仓库保留了脚本本身，没有复制这些外部原始输入和全部中间产物。空克隆可以查看工具源码；不能保证直接运行所有分析入口。优先使用仓库根目录说明中的重建工程构建及已随仓库提供的独立测试。

需要重新执行分析时，准备合法获得的原 APK 和对应分析产物，再显式配置路径：

```sh
export XCS_REVERSE_APP_ROOT="/path/to/local/APP"
export JAVA_HOME="/path/to/jdk"
python3 reverse/scripts/verify_deep_extract.py
```

`XCS_REVERSE_APP_ROOT` 应指向外部输入目录。部分脚本接受工作区根目录并在其下追加 `APP/`，因此该目录名称应为 `APP`。公开副本通过 `scripts/_paths.py` 读取配置；不再使用开发者本机的绝对工作区路径。跨项目 JAR 旁证脚本另支持 `XCS_REVERSE_STUDY_ROOT`。Ghidra 驱动脚本支持 `GHIDRA_ANALYZE_HEADLESS`，其值为本机 `analyzeHeadless` 命令的路径。Python 入口根据实际用途还可能需要 `pyelftools`、`capstone`、`unicorn`、LLVM、Ghidra、Blutter 或对应 Dart VM C++ 头文件。

工具可能在外部输入树或自身分析子目录写入生成的证据和报告。运行前阅读其输出路径；生成物不会自动成为已恢复的源码。`round_tools/` 中的历史最终报告生成器依赖各轮当时的报告、哈希和产物布局，不应直接用于重新认证当前公开副本。

## 历史记录与脱敏

TXT 报告中的具体本机路径已改为 `<LOCAL_APP>`、`<LOCAL_WORKSPACE>`。`coverage_ledger.historical.json` 同样进行了路径脱敏，并附有 `_public_copy` 字段和原文件 SHA-256。台账保留历史审计的缺口与范围，不能将路径脱敏后的哈希当作原始台账哈希。

报告和脚本中的 `reconstructed`、`pseudocode` 等字样属于历史分析表达；它们不等于原作者源码，也不作为已完成实现的证明。可执行重建代码及其验证范围以仓库根目录工程说明和测试为准。未复制的原始输入可能仍被历史报告引用，因此这些引用在公开仓库中不保证存在。

发布前已进行秘密格式扫描。扫描只报告文件名及命中类别，不输出秘密值；保留原工程和公开副本的隔离，避免把原始密钥或未检查的生成物提交到公开仓库。
