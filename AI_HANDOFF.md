# AI_HANDOFF.md —— AI 助手交接文档

> 给下一个接手本项目的 AI：先读完这份，再动手。所有内容以 2026-10-28 为准。

## 项目是什么

ScholarVPN：三平台（Windows/Linux/Android）学术 VPN 客户端 + Linux 服务端 + Web 管理端。
当前版本 **1.7.0**（versionCode 2），已公网部署更新体系，历史已整合为单提交 `27a2edf`（main）。

## 仓库与分支

- 远程：`git@github.com:hhhjb263-art/ScholarVPN.git`，**推送走 443 已全局配置**（22 被墙），直接 `git push` 即可
- 分支：`main`（产品）/ `server` / `client`（均未合入 1.7.0 改动，已废弃倾向但未删）
- 工作区根有 `UpdateApp.cpp/h`：**用户半成品，保持 untracked，不要提交不要删**

## 代码地图

| 模块 | 路径 | 说明 |
|---|---|---|
| 流量分流 | `src/platform/{cidr,iplist}.h*`、`src/route_manager.*`、`src/client/ClientApp.*` | 国内 4318 条网段 bypass；`docs/routing/chnroute.txt` + `scripts/gen_chnroute.py` |
| 更新系统 | `src/update/{policy,fetcher,checker,install}.*`、`src/gui/AppBridge.*` | 策略拉取→Ed25519 验签→决策→下载(SHA-256)→安装→强制约束 |
| Android | `android/app/src/main/java/com/scholarvpn/client/` | Kotlin+Compose；`update/UpdateChecker.kt`（策略地址分段 Base64 混淆+多通道候选）|
| 更新服务端 | `scripts/sign-update-policy.py`（make/sign/verify） | 签名策略+防呆（拒绝 minimum>latest） |
| 构建 | `scripts/build-linux.sh`、`scripts/update-version.py`、`scripts/package.bat` | Linux 一键构建；版本号单源（version.h → iss 同步） |
| 设计文档 | `docs/流量分流设计.md`、`docs/客户端更新策略.md` | 先读这两份再动对应模块 |

## 构建（各平台，都是 Release）

- **Windows**：⚠️ MSBuild 被安全策略拦，用 **cl.exe/link.exe 直编**（参数：`/MD /DNDEBUG /std:c++20 /EHsc /utf-8 /Zc:__cplusplus` + Qt/OpenSSL include）；产物重命名 `ScholarVPN.exe` 放 `x64/Release/` 供 Inno（`D:\Program Files (x86)\Inno Setup 6\ISCC.exe`）打包；**.rc 资源（图标/VERSIONINFO/UAC）要手动 rc.exe 编译进 link**
- **Linux**：`scripts/build-linux.sh`（--clean/--install），版本号自动读 version.h；**必须在项目内跑**（按自身位置定位根）
- **Android**：`android/gradlew assembleRelease`（正式签名在 keystore.properties，已配置）

## 发布部署（四步，产物到 `dist/`）

```bash
# 1. 策略 make（哈希/大小必须脚本算，禁止手写——教训见下）
python scripts/sign-update-policy.py make --key dist/keys-release/release.key \
    --latest <ver> --minimum <ver> --url <包URL> --sha256 <sha> --size <size>
# 2. sign + 3. verify  4. 上传三件套到 189:/var/www/scholarvpn-update/
```

- **上传必须逐文件单独管道**：`cat 文件 | ssh root@189 "cat > 目标"`——
  ⚠️ 绝对不要一条 ssh 喂多个 `cat >`（stdin 只进第一个，其余写 0 字节空文件——踩过）
- 上传后校验远端 `sha256sum` 与本地一致
- 189 的 shell 有 **proxy 环境变量**，curl 必须加 `--noproxy "*"`，否则全 000 误判服务挂了
- **服务器 IP（189.24.71.179）正被间歇性端口阻断**：22 时通时断，8444 对部分网络不可达；
  SSH 操作要带重试；Android 端 `POLICY_CANDIDATES` 已预留多通道结构，可追加备用 URL

## 红线（违反会被骂）

1. **webadmin / server 代码不动**：改客户端不得影响 `scholarvpn.homes` 后台服务（用户 2026-10-27 明确要求）
2. **`dist/keys-release/release.key` 是信任根**：丢了所有客户端收不到更新，泄露了别人能签发强制更新——反复提醒用户备份
3. **删除类操作**（数据/分支/文件）必须明确确认
4. **敏感信息不出现在客户端**：IP/域名/端口不硬编码、日志/UI 不打印（Android 策略地址用分段 Base64，学 `UpdateChecker.kt`）
5. **版本号单源**：只改 `src/version.h`，然后 `python scripts/update-version.py` 同步 iss——
   手工双处改曾造成"更新后还显示未更新"的事故
6. **哈希/大小等一切数据从文件实际计算**，禁止手写截断值（踩过：编造哈希写进策略）

## 已知坑（都是踩过的，别再踩）

- 坑死人的：项目路径含空格（`D:\Vis  c++\`），MSBuild 参数要处理；bash 会把 `/nologo` 当路径转换，Windows 工具用 PowerShell 调
- 阻塞 `connect()` 不受 `SO_SNDTIMEO` 控制——必须非阻塞+poll（已修，见 `update_fetcher.cpp`）
- SSH 远程启动 Linux GUI 会被 logind 会话清理杀掉（setsid 也保不住）；要远程起 GUI 用
  `systemd-run --user --setenv=WAYLAND_DISPLAY=... ...`
- 服务器/本机的 curl 记得 `--noproxy "*"`；诊断服务器先 `env | grep -i proxy`
- 多文件 scp 一个失败 = 整批失败，传完逐个验证（main.cpp 曾静默丢三轮）
- `io.open(...).write()` 后立刻 read 是旧内容（Windows 缓冲）——用 `with` 语句
- VS 报 IntelliSense 错误以 cl 编译结果为准；程序化改代码后必须 grep 确认无重复块

## 待办（接下来可做的任务）

1. **Linux 发行恢复**：VM（192.168.233.131/10.22.24.231，开机后 SSH user/密码123）恢复后重编
   探针清理版 → 上传 tar.gz → 策略加回 linux-x64 字段重签上传（现在策略里 linux 字段是移除状态）
2. **Android IP 分流**：VpnService 无法路由层绕过 TUN，需应用层转发（TUN 读包→国内直连
   socket+protect()），大工程待做
3. **189 被墙对策**：多端口副本+客户端 fallback / CDN 中转 / 换 IP——用户未拍板
4. **`UpdateApp.cpp/h`**：用户半成品，问用户是否继续或删除
5. **Application Verifier** 长期跑一次（确认已消失的堆问题不复发）

## 用户偏好（怎么服务这位老板）

- **要代码不要截图**；交付以代码、file:line、编译/运行日志为主
- **快**：能并行就并行，能自己验证的别等
- **诚实标注未验证项**，"看起来好了"≠"验证通过"
- 出错直接认，别遮掩；用户明确说过"出错骂我"（骂事不骂人）
