第二轮：预览异步回调、RxString、结果编辑状态

范围与结果
本目录是原 APK 证据支持的 Java 功能重建及测试，不是 Flutter/Dart 原始源码。没有从本审计联系业务服务器、使用账号凭据或执行原 App 的 Dart 业务入口。
callback_contracts.json 保存逐项语义、原始入口、闭包引用、动态 receiver 证据、原始字节和重建文件哈希。
verification.json：35 个业务方法证据体、10 个框架入口、2895 条 ARM64 指令复核 PASS；其中 14 个业务方法从冻结清单的无显式语义关联变为本轮有界关联。整方法完成数仍为 0，不修改冻结审计。
test_results.json：124 个实际 Java 状态断言 PASS。测试是本地重建代码测试，不是原 APK 与重建 APK 的动态差分。

原始证据与新增发现
1. 请求用 PreviewService.field_b，初值 0；WS102 用 MainService.field_f，初值 -1；预览图像由 MainService.field_b 的全局 RxString 保存。三者不可合并。
2. startPreview 发请求前写 serviceDeviceId；普通响应回调读取捕获 Devices 对象的当前 id，null 变 0，不查 HTTP ok/success。异常或未完成 Future 不执行该回调。乱序完成以最后一次回调为准。
3. save/end 先把 serviceDeviceId 置 0。保存失败没有回滚；用户再返回时父路由看到 0，不再补发 end。原服务 ID 为 null 时，由于 null != 0，父路由仍发 /end_preview/null。
4. 保存的 close 模式必须 ok 且 success 为严格 bool true。随后使用捕获设备的当前 id 发 end，挂接共享完成闭包，立即 pop(true)，不等待 end。原页面已销毁时也先执行 end，然后可能在读取 State.element 导航时出错。
5. 共享 0x6f2a58 只有 mov x0,x22; ret（e00316aac0035fd6），确实只返回 null。Java sharedNullCompletion 的空效果对应已证明机器码，不是占位实现。
6. 退出不清 filter/frame。重新进入只把 RxString 赋空，不自行 start；新 start 响应到达前，旧 filter 仍可接收旧设备图像。未带前缀的 WS102 仍然直接更新。
7. RxString.value= 先检查 GetStream 是否已关闭；字符串相等且非首次时忽略。初始 first=true，所以首次赋相同空串仍发通知，之后相同值不发。已用原 snapshot 的 GDT 元数据证明 OneByteString/TwoByteString 的相等接收者，而非根据函数名猜测。
8. WS102 解码失败发生在 setter 之前，旧帧保留。base64/图像渲染失败发生在值写入之后，不应回滚。重复图像抑制来自 RxString 相等检查，不是 WS 协议序号或重放校验。
9. 结果编辑模式初值 1；打开为 2；关闭是 mode==1?0:1。显示模式初值 2，切换是 type==2?1:2。切换不清选中对象。选牌后仅在显示模式 2 隐藏选择面板，仍保留所选 ChannelResult 对象。
10. 上传成功逐通道设置 pageMode=1、分配新的空结果 List、按显示模式 2 隐藏面板。零通道则不发生这些循环内效果。所选对象及删除偏移不被清空。
11. WS113 也替换结果 List，而非对旧 List.clear。HTTP 图像晚到回调读取当前列表，可能进入下一轮。新测试保留旧 List 引用并确认其内容不受新轮次清空影响。
12. HTTP401 的动态数值比较接受 code=401.0，也接受整数401，拒绝字符串"401"。SessionState 修正此前过窄的整数类型判断；原始拦截器待完成 Future 与页面导航仍未完整模拟。

给 Android UI 的接口
MessageEngine.enterPreviewPage()
  页面初始化只清全局图像值；开始某设备需要另调 startPreview。
MessageEngine.startPreview(Models.Device) -> ApiContract.Request
  请求前写 serviceDeviceId。执行请求后，把正常 Future 值交给 onStartPreviewValue(capturedDevice,response)。必须传捕获的设备对象，不能只保存 ID 快照。
MessageEngine.savePreviewParams(Number,Map) -> ApiContract.Request
  保留清 serviceDeviceId 的时序；本函数没有网络 I/O。
MessageEngine.onSavePreviewValue(Models.Device,boolean,Response) -> PreviewSaveOutcome
  outcome.endRequest 非空时先提交该请求，然后按 popWithTrue 导航；不要等待 end 成功才退出。UI 生命周期保护由 UI 明确选择。
MessageEngine.endPreview(Number) -> Request
MessageEngine.onPreviewRouteReturned() -> Request/null
  所有普通退出路径使用父路由回调。第二次调用看到 0 返回 null。
SessionState.preview 持有跨预览路由的服务状态；engine.currentPreviewDeviceId/previewFrame 保留兼容读取，新 UI 不应直接赋值。
ResultRules.openChangePage / closeChangePage / toggleDisplayType / openPalette / closePalette
ResultRules.selectResultForEdit / cancelResultSelection / selectMain(SessionState,Map)
  只执行已证明状态写入；Android UI 自己实现控件和导航。

明确差异和剩余限制
- Java 是原生 Android 功能重建，不能还原原 Flutter 控件树、布局、动画、注释、符号名或项目构建文本。
- Android 主线程、generation、mounted 保护及 MessageEngine.close 后抑制晚到图片回调是重建生命周期策略；原函数没有同样的保护。不能将该差异描述成原 App 的清理行为。
- Java Listener 同步调用没有完整重现 GetStream 订阅、派发时序、异常传播或 Flutter 重绘。
- HTTP 普通异常被包装成 ok=false、非 Exception 重新抛出、特定401导致 Future pending 这些完整 Dart/Future 语义仍属原始证据中的边界；本状态 API 不模拟所有 Future 调度器。
- 连接状态与认证状态仍独立；断线/认证恢复未在这些预览回调中出现自动 start/end。真实设备恢复效果必须靠服务器、设备与原程序实验验证。
- 动态 msg_content.toString 通过 DartConversions 的已支持 receiver 集合执行；Mint/自定义 receiver/循环容器等未闭合路径明确抛 UnsupportedOperationException。

复跑
在本目录执行 ./run_tests.sh，可重新编译全部 core Java 并打印带断言明细的 JSON。
原证据复核脚本：APP/analysis/reconstruction_round2/callbacks/build_callback_contracts.py。
原 snapshot 元数据工具源码/构建参数：同目录 snapshot_callback_targets.cpp 与 snapshot_tool_build_commands.json。
工具只读取 snapshot 的类、分发表和方法地址，没有调用目标 Dart 方法。
