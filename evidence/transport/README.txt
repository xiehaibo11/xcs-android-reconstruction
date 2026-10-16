WebSocket 独立主机网络测试

运行：python3 APP/reconstruction/evidence/transport/run_network_tests.py
需要允许本机进程绑定/连接 127.0.0.1；不联系业务服务器。
测试编译实际 app/src/main/java 下的 WsWire/WsSession/JsonCodec/ApiContract/Models，并通过 Python TCP 对端发送真实握手及帧。
WsNetworkProbe.java 只在 evidence/transport 作为主机测试编译，不进入 APK。
生产 WsSession 构造器仍固定 18889；包内可见的第二构造器仅给独立测试注入动态端口，避免占用其他本地测试服务。

真实网络场景
1. RFC6455 升级握手与随机 nonce；客户端掩码；126/65536 字节长度；分片 UTF-8 跨字符边界；分片间 ping/pong；合法 close 回显。
2. 拒绝服务端掩码、RSV、非最短长度编码、无前导分片的 continuation、当前重建不支持的 binary、非法 UTF-8、分片 control、1字节 close、保留 close 状态码、错误 upgrade accept。
3. token 登录 types=6；非法认证载荷报告错误；成功认证后立即发送 types=1 心跳。
4. QoS 认证确认的 ACK；业务 QoS 重复两次 ACK、只派发一次，from/to 对调。
5. 内层 msg_type 类型错误不再错误地断开整个传输；重复 start 明确拒绝。
6. TCP 断开后重连；未收到认证时每 3 秒重发 types=6；非零认证响应不发送 ACK，停止此次重连循环。
7. types=54 关闭传输并停止后续重连。
8. 使用生产原值实际等待 30 秒心跳；types=51 回包延迟 4 秒验证超时计时刷新；35 秒无回包加 2 秒检测周期触发重连；重新认证后恢复心跳；logout 发 types=3 并清连接/认证状态。

另外的直接回归检查
测试通过反射把旧 generation 的模拟数据交给 receive，确认旧 reader 不再派发业务消息。此项明确是直接状态回归检查，不能描述成 Rust 竞态动态复现。

本轮修复的重建代码缺陷
WsWire：初始化失败关闭 socket；校验 close 状态码；close 不再等待 frame 写锁；已关闭后发送显式失败。
WsSession：重复 start 不再创建第二条连接；旧 generation reader 不再污染当前会话；旧 reader 异常不再作为新会话错误报告；内层业务字段 IOException 只报告消息错误；结束会话清理去重表。
这些更改是重建工程的明确实现策略/健壮性修复，不宣称原 Rust 同样如此。

结果与边界
network_verification.json 记录每组 PASS/FAIL、真实时长、Java 回调/客户端数据包和参与源文件的 SHA256。
只有整组均通过才写 status=PASS。先前出现过测试 fixture 在 logout 后再次向已退出 Java stdin 写 close 的 BrokenPipe，现使用 ending 标记消除该测试进程退出竞态，没有删除 logout 网络和状态断言。
这里验证的是新 Java 实现，未执行原 APK 或 Rust SO；rust_concurrency_equivalent=false，original_source_recovered=false。
没有覆盖 TLS、扩展、二进制业务帧、完整 QoS 发送缓存/重发、任意阻塞回调/阻塞写入下的调度，以及业务服务器行为。上述未实现/未验证内容不能按恢复完成验收。
