业务核心重建交付说明（2026-10-14）

性质
这些 Java 文件是依据本 APK 静态证据重新编写的可执行实现，不是恢复的原始 Dart、Rust 或 Go 文件。
未使用反汇编或伪代码文件作为编译输入；缺失分支明确列出，未以空返回成功代替。

已实际实现并通过本地测试
1. 22 个固定 HTTP 请求构造器，动态图片 URL；预览19字段类型/拼写、JSON数组上传、原样密码、更新 query。
2. JSON parse/stringify；默认重复key保留最后值，parseStrict为WS新增拒绝所有重复key模式。
3. 基于 HttpURLConnection 的真实 HTTP transport：headers、JSON body/query、GET/POST空body、响应状态、401双条件清JWT。
4. HTTP登录 -> JWT/User/Devices -> 获取服务器配置 -> PKCS#1 v1.5 RSA私钥解密 -> UTF8/JSON ->业务host/图像规则->设备排序->检查更新。
5. 94 个已观察模型字段的类型合约。第二轮已确认 Devices.version 为动态 toDouble、Message.msg_content 非空转 String。支持已确认常见接收类型；Devices.create_time 的 DateTime 行为仍明确未恢复，因此该模型完整 toJson 仍抛出 UnsupportedOperationException。
6. 7个消息接收分支101/102/113/114/115/116/117：图像获取缓存、预览设备过滤、接收计时、延后5秒数量检查、设备状态。101占位不GET、不触发完成统计；自动完成用recognized==expected。
7. 牌数量校验、上传JSON数组、手工选牌、主视图删除重编号及offset、左视图删除不重编号；上传成功清理实时channels。
8. 本地登录配置、ViewSetting固定默认值行为、口令MD5写盘；不添加未知入口口令读取或验证。
9. endGames成功后的倒计时/状态恢复。调用者必须按原回调严格bool true判断，不能套通用success!=false。

接口
ApiContract.Transport.execute(Request) -> Response，阻塞；UI应在worker调用。
LoginFlow(session,transport).login(ip,username,password,pubPem,privatePem,version) -> Result(updateCheck,unresolved)。
登录HTTP成功不等于WS连接或认证；此类不设connected/authenticated=true。
MessageEngine(session,ImageLoader,Listener,ScheduledExecutorService)，accept(Map)。
Listener changed/status/preview/readyToValidateAndUpload/shortfall/failure；UI回调需切回UI线程。
CachedImageLoader是真实GET->替换->Base64->写文件实现，ImageLoader回调不允许伪造网络成功。
LocalConfig为同步文件I/O工具；原Flutter外层不await行为由UI控制层决定。
Models.Record.values是有界字段快照，不应当成完整原始模型序列化器。

明确无法恢复或尚未实现
- 原Dart工程结构、注释、变量名、被树摇/内联消去的代码、原Flutter组件和所有库源码。
- DateTime.parse/ISO 序列化所有边界；Message.toString 的 Mint、自定义接收类型及循环容器格式。普通 String/bool/Smi/Double/List/Map 的有界转换见 evidence/round2/models。
- 原完整Rust WS/QoS/FRB状态机由另一模块处理，此业务核心不伪造认证。
- msg117第二段意义、inlet_pwd读取/认证入口、任意未知 msg_type、完整后端规则。第二轮已通过用户指定账号的真实登录与只读配置链路；完整设备约束仍未验收。
- 原UI全部布局、图像重编码/旋转、所有设置联动及资源展示；本类仅给可执行业务数据流。
- 明确的原模型字段但无消费者闭合者保留原值；不猜枚举、范围、默认后台语义。
- Cookie持久化原为临时目录PersistCookieJar，此Java transport仅进程内CookieManager；跨进程cookie不等价。
- JSON超出signed64位整数、特殊Unicode/时间格式、Dart num与Java数字边界的全部兼容未验证。
- 此实现缺少Dio所有超时/取消/重定向细节，不能认定完整网络错误时序等价。
- MessageEngine.close主动丢弃关闭后的图像回调并取消延迟任务，为重建资源管理选择；原页面销毁的全部时序未闭合。
- 原101异步调用没有catch，重建将错误交Listener.failure；不把这些错误包装为业务成功。
- 主机测试中的mock仅测试夹具；运行工程未植入成功假响应，不默认使用demo登录。

验证
BusinessCoreTest.java 64条本地行为断言：JSON、HTTP参数、模型严格类型、401双条件、结果数量与删除、7消息/延迟状态、文件I/O、实际PKCS#1 PEM解析/RSA合成密文往返、两阶段登录请求顺序。
测试无网络请求，RSA使用APK原key解析并加密本地合成字符串；未输出密钥或真实凭证。
run_tests.sh 可复验。通过主机核心测试不是Android运行或服务端端到端通过。

精确证据
source_map.json记录每个重建文件对应证据、方法地址及来源SHA256。
原审计coverage_ledger保持冻结；不将此处可编译文件反写为387方法全部闭合。

第二轮补充
evidence/round2/callbacks 记录 124 条回调/状态断言及原机器码复核；预览开始、结束、保存、路由返回与共享空回调已接入 Android 页面。WS113/上传成功分配新的 results 列表，保留旧列表引用。回调正常返回值、Future 错误和无完成事件分别处理。
