# APP 全量工作区快照

本目录上传了快照时点整个本地 `APP/` 目录：**42,534 个文件、4,321 个目录、3,153,516,657 字节源文件**，没有排除任何当时存在的文件。

原始 APK、解包结果、SO/DEX、JADX/apktool/Ghidra 分析、脚本、参考 SDK、工具 Git 历史、重建工程、构建与交付产物、日志、模拟器运行目录，以及当时的公开发布副本及其 Git 元数据均按原路径保留。用户已明确要求原应用私钥和生产凭据也公开，因此全量归档没有继续使用首版源码发布的排除规则。快照只覆盖 `APP/`，未读取或收集电脑其他目录中的凭据。

## 归档与校验

- `parts/`：完整 `APP-complete.tar.gz` 的 7 个有序分卷，通过 Git LFS 保存文件本体。
- `parts.json`：每卷路径、字节数、SHA-256 和完整归档摘要。
- `files.jsonl`：全部文件/目录的原路径、字节数、权限和文件 SHA-256。
- `snapshot.json`：快照时间、范围、统计及归档 SHA-256。
- `verification.json`：全部归档成员与清单逐项核对、源文件前后完整性验证的结果。
- `snapshot_app.py`：快照与完整性验证工具。
- `restore_snapshot.py`：校验每卷后拼接、验证完整归档 SHA-256 的工具。

完整归档为 **1,843,151,831 字节**，SHA-256：

```text
831189b605e0d0ca5ba88cb55010b1da07ea2fe3ae8475300163f399c934f1c9
```

本地逐项验证已经核对全部 42,534 个文件的内容，并确认快照期间源文件及路径集合未变化，0 个错误。远端下载验证另见上传后记录的 `remote-verification.json`。

`APP/public/xcs-android-reconstruction/.git` 保存全量上传前的仓库状态。新创建的本归档及分卷不属于其记录的此前时点，不会递归打入自身。仓库根目录现有可浏览源码和测试继续保留。

## 获取与解压

安装 Git LFS 后，克隆并拉取分卷，运行校验恢复工具，再在独立目录解压：

```sh
git clone https://github.com/xiehaibo11/xcs-android-reconstruction.git
cd xcs-android-reconstruction
git lfs install --local
git lfs pull --include="full-workspace/parts/*"
python3 full-workspace/restore_snapshot.py --output ../APP-complete.tar.gz
mkdir -p ../xcs-full-extracted
tar -xzf ../APP-complete.tar.gz -C ../xcs-full-extracted
```

GitHub 文件页面可能显示 Git LFS 指针说明；完整分卷由 Git LFS 提供。`restore_snapshot.py` 会拒绝使用没有下载成功的指针文本、哈希不符的分卷及已存在的输出文件。

解压后的内容是完整原始工作区快照，包含旧报告、旧构建和工具版本。上传已有二进制、伪代码和中间文件，不代表未恢复的原始源码已经恢复；重建范围和已知缺口仍以工程说明及审计报告为准。
