公开副本说明：本文件为历史分析报告，具体本机路径已脱敏为 <LOCAL_APP> 或 <LOCAL_WORKSPACE>；报告中的历史完成状态不代表完整原始源码已恢复。

本目录为 app_xcs(新).apk.1.1 的静态逆向工作区。

先阅读：逆向完整性审计与补齐报告.txt（最新审计：整包大小写资源碰撞、DEX全定义、612方法、16模型、13原生库、补链及明确未闭合清单）
前轮重连：断线重连与预览失败恢复还原报告.txt（首次连接失败、重登/拒绝后续、HTTP401等待、晚到WS102及异步状态恢复）
前轮连接及退出：连接判定与预览退出补全报告.txt（isContentWs实际判定、认证状态、共享回调和预览退出清理）
设备及运行状态：运行状态与设备控制深度还原报告.txt（已同步纠正旧isContentWs入参及回调未知项）
前轮WebSocket：WebSocket与识别上传流程还原报告.txt（消息格式、心跳/QoS、识别校验及上传链）
前轮登录及接口：登录与业务协议还原报告.txt（22个接口参数和7类msg_type）
前轮基础结果：深度提取报告.txt；初次解包及工具：逆向分析报告.txt
工具清单：analysis/local_tools.json
接口清单：analysis/flutter/api_candidates.json
完整HTTP合约：analysis/http_endpoints_all.json（22个固定模板及动态图片GET）
登录流程、RSA配置解密及原生重登：analysis/login_flow/
HTTP参数Schema与方法证据：analysis/http_contract/
msg_type映射、消息模型及可读分发逻辑：analysis/message_semantics/
WebSocket外层9类types、JSON Schema及16个合成示例：analysis/ws_protocol/
心跳、重登录、QoS、退出流程及原生补充伪代码：analysis/ws_heartbeat/
识别、人工修改、校验及HTTP上传完整流程：analysis/result_pipeline/
Rust→FRB→Dart→HTTP交叉证据及原ELF调用校验：analysis/ws_result_integration/
设备/牌局/预览18条操作链、14个既有接口模板、91个完整方法：analysis/device_lifecycle/
图片响应规则、离线codec和合成边界验证：analysis/image_codec/
启动、3个配置文件、会话存储及ViewSetting默认值问题：analysis/local_state/
Rust→FRB→Dart事件契约、认证/关闭与初始化配置：analysis/ws_event_contract/
连接判定、认证状态及预览清理补全：analysis/connection_preview_closure/（is_content_ws、end_preview、state_audit、stream_lifetime四组证据）
断线重连、Close帧构造及写出尝试：analysis/reconnect_preview_failure/reconnect/
原生认证拒绝、本地wsLogin结果和心跳超时：analysis/reconnect_preview_failure/authentication/
结束失败、晚到WS102、start乱序及图片Future：analysis/reconnect_preview_failure/preview/
HTTP失败包装、特殊401未完成handler及Dart/native JWT边界：analysis/reconnect_preview_failure/dart_http/
前轮更正：ws_heartbeat/heartbeat_lifecycle.json 中 stale_heartbeat_after_relogin 已被最新报告覆盖；完整stop-heartbeat尾部会将时间戳清0。
公开来源归属检索及协议家族对照（含未确认项）：analysis/open_source/
AOT方法汇编、对象池：analysis/aot_dump/
方法索引及原始ELF直接调用验证：analysis/aot_runtime/
原生入口伪代码：analysis/ghidra/
Rust 深度伪代码及协议 Schema：analysis/deep_rust/
Flutter 业务符号、字段候选：analysis/deep_flutter/
Go RSA 函数及 FlatBuffers 请求表：analysis/deep_rsa/
Android 通道、参数和存储编码：analysis/deep_android/
Ghidra 项目：ghidra/xcs_native.gpr

最新统一审计脚本：python3 scripts/verify_completeness_audit.py（在APP目录执行）
最新审计检查：analysis/completeness_audit/verification.json（字节/库存/证据一致性PASS；完整业务语义仍为false）
分层覆盖及缺口：analysis/completeness_audit/coverage_ledger.json
整包可逆条目索引：analysis/completeness_audit/android/zip_inventory.json（旧unpacked无法原名同时保存4C.xml/4c.xml）
全612业务方法正文与机器码：analysis/completeness_audit/flutter/complete_methods/、raw_methods/
模型94个类+键合同：analysis/completeness_audit/models/model_field_contracts.json
13库/4ABI及全原生函数库存：analysis/completeness_audit/native/native_completeness.json
认证JSON措辞纠正：types50 user_id/data只确认局部String解析及释放，未证明保存SDK；差异记录见completeness_audit/android/corrections/
前轮重连统一脚本：python3 scripts/verify_reconnect_preview_failure.py
前轮重连检查：analysis/reconnect_preview_failure_verification.json（PASS）
前轮连接补全检查：analysis/connection_preview_closure_verification.json（PASS）
前轮连接补全检查脚本：python3 scripts/verify_connection_preview_closure.py
设备及运行状态检查：analysis/runtime_reconstruction_verification.json（更正后重新PASS）
设备及运行状态检查脚本：python3 scripts/verify_runtime_reconstruction.py
前轮WebSocket检查：analysis/ws_result_reconstruction_verification.json
前轮协议检查：analysis/protocol_reconstruction_verification.json
前轮检查：analysis/analysis_status.json 与 analysis/deep_verification.json。
完整原始 Dart 源码尚未恢复；aot_dump/*.dart 内容是注释汇编，不是可编译源码。
