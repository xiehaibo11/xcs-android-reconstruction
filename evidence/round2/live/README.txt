真实只读验证（2026-10-14）

Android API35 的 LiveLoginChecks 使用与24项本地Activity检查相同的已签名APK，6项检查通过，实际请求范围见 android-verification.json。登录、服务器配置、更新检查、牌配置、在线配置、设备状态共6个HTTP请求全部200；更新检查success=false为未提示升级分支。读取4台设备、50项牌配置，WS状态先connected=true/authenticated=false，再true/true。报告只保存状态与数量，不包含账号、密码、JWT、设备身份或原始返回数据。

测试没有实例化MessageEngine，不会响应业务消息而触发上传；HTTP路由使用精确白名单，未调用生产预览、设置保存、开始/结束、重启、密码修改或识别上传。WS可执行认证和立即心跳。真实账号的失败登录/反复认证拒绝/断线恢复、真实识别与上传尚未测试。

主机先前已使用LiveLoginProbe.java完成相同范围，但只保留控制台观察，不把它冒充独立原始抓包。可复验的当前交付证据以 Android 报告为准。

最初两次Android尝试在凭据输入前停住：adb am instrument子进程继承stdin抢读，已主动终止；脚本现将该子进程stdin设DEVNULL并使用fd0非回显读取。最终报告来自修复后的实际运行。凭据经临时adb本地socket送入App内存，未写入源码、配置或交付包；测试结束关闭WS及临时forward。

复验命令：python3 scripts/run_live_login_checks.py --serial emulator-5580 --adb-port 5038
需要显式启动的隔离模拟器和终端；在提示后输入host、username、password组成的JSON。程序不会从源码提供默认凭据。只有用户授权的账号应参与该测试。

最终复验前已修复旧报告复用风险：每轮先删除App私有旧报告，读取新报告后与本轮instrumentation流中的JSON完整比对（兼容裸JSON或带stream=前缀）；只有一致才标PASS并附上APK哈希。最终Android验证使用修复后的脚本执行。
