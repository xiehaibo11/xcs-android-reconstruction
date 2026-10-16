公开副本说明（2026-10-16）
本树含历史证据与经过路径脱敏的报告；历史哈希仍指向当时本地交付。
公开版当前构建与测试请看 ../PUBLIC_VALIDATION.json；runtime 截图/日志和密钥未进入Git。
以下保留原交付说明用于理解证据边界，不等于公开副本已经重跑历史 Android/生产验收。

证据阅读说明（第三轮，2026-10-15）

当前源码与测试以 round3/integration/host-verification.json、runtime/verification.json、
round3/live/android-verification.json 及 dist/source-build.json 为对应关系。
最终交付检查见 ../dist/delivery-verification.json；独立ZIP复建见 ../dist/standalone-build-verification.json。
这些报告均绑定具体源码或 APK SHA-256，不能把旧报告的通过结论自动用于新文件。

round3/datetime、round3/mint、round3/numeric_json 与 round3/simd 分别保留原始静态证据、
参考运行/机器码运行、便携录制结果与实际可编译测试。参考SDK/VM执行、原机器码片段执行、
新Java工程测试是不同层次；报告中注明的外部调用模型和时区数据库边界仍然有效。
GoBytePrimitives 是可执行语义实现，已编入APK并单测；没有已证实的业务调用点，
因此没有擅自替换现有RSA登录调用，也没有把原NEON的内存读取行为当作Java实现要求。

round2 和更早的 verification、contracts、原样保留的失败日志属于各轮当时的证据。
部分可执行回归测试为了验证当前实现已经更新；第三轮实际执行结果统一记入
round3/integration/host-verification.json。第二轮完整源码与APK快照保存在工程
外于此evidence树的 dist/history/round2，不随当前源码ZIP重复打包。
旧报告中 DateTime/Mint 尚未恢复的说法是当时状态，最新边界看 gap_progress.json。

原冻结审计 ../../analysis/completeness_audit/coverage_ledger.json 不在独立源码ZIP内；
它在完整 APP 目录中，12类baseline未改变。gap_progress.json保留这些对象并逐项更新
限定范围进展，未声明完整原源码或全部业务等价。绝对路径引用是本机证据定位，
移到其他机器后可能不可访问，不能据此认为外部分析输入已经随源码ZIP交付。
