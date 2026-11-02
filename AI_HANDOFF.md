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

- **Windows**：**MSBuild 可用**（2026-10-31 实测，bat 包一层跑 `MSBuild.exe VPN_.vcxproj /p:Configuration=... /p:Platform=x64` 即可；此前"被安全策略拦"的信息已过时）。cl.exe/link.exe 直编仍是回归手段（参数：`/MD /DNDEBUG /std:c++20 /EHsc /utf-8 /Zc:__cplusplus` + Qt/OpenSSL include）；发布产物重命名 `ScholarVPN.exe` 放 `x64/Release/` 供 Inno（`D:\Program Files (x86)\Inno Setup 6\ISCC.exe`）打包
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

1. **webadmin / server 代码改动须受控**：2026-10-31 用户已授权在「受管服务模式」功能范围内
   最小化修改 server（UDP.cpp/VpnCore 数据面+登录校验）并扩展 webadmin（见
   `docs/受管服务与试用授权方案.md` 第 6/7 节的约束）。范围外仍不动，尤其不得影响
   `scholarvpn.homes` 既有后台服务的可用性（用户 2026-10-27 明确要求）
2. **信任根有两把，都要备份**：`dist/keys-release/release.key`（更新策略签名）与
   `dist/keys-service/release.key`（受管服务签名，2026-10-31 新建；公钥已编译进
   `src/service/service_bootstrap.h`）——丢了客户端收不到更新/服务全断，泄露了别人能
   签发强制更新或伪造服务器列表，反复提醒用户备份
3. **删除类操作**（数据/分支/文件）必须明确确认
4. **敏感信息不出现在客户端**：IP/域名/端口不硬编码、日志/UI 不打印（Android 策略地址
   用分段 Base64）。**例外（老板 2026-10-31 明确要求）**：受管服务接入点
   `scholarvpn.homes:8444` 随发行版内置在 `service_bootstrap.h`（对外前台域名，与更新
   静态源同域）；后台管理域名/端口仍严禁出现在客户端
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
- **新增源文件必须同步登记三处**：`VPN_.vcxproj`（ClCompile/ClInclude）+ `VPN_.vcxproj.filters`
  + `CMakeLists.txt`——漏登记在 AI 直编时能过、MSBuild 链接时才爆 LNK2019（2026-10-31 踩过，
  service 两个 .cpp 漏了）；同理 GUI 头文件改了信号/槽必须重新跑 moc 更新 `src/gui/moc_*.cpp`
- bash 里写含中文/反斜杠的 bat 用 python `with io.open(...)` 写（Write 工具偶发拒收，
  printf 转义层叠会把 `\n` 写成真换行）

## 受管服务部署现状（2026-10-31）

- broker 已上线 189：`/opt/scholarvpn-broker` + `scholarvpn-broker.service`（0.0.0.0:8445
  自带 TLS，证书复用 server/tls/，令牌写 server/keys/register_tokens.txt）。
  客户端内置 `https://scholarvpn.homes:8445` + service 公钥（`service_bootstrap.h`）。
- 服务器 root 登录用 askpass 脚本（`%TEMP%\.svp_askpass.sh`，本会话产物，含密码，
  部署阶段结束后应删除）；公钥尚未安装到服务器 authorized_keys。
- vpn-server 侧已上线（2026-10-31 重编部署）：trials 登录校验/deny 原因码 2、
  会话流量 30s 批量落库 + 2GB 切断、DNS/SNI 审计 + 黑名单（SQL 在 server/ServiceDB.cpp，
  依赖 libsqlite3-dev；SVC_DB=/opt/scholarvpn-broker/service.db 已写入
  /etc/default/vpn-server）。列表下发已加 fp 门槛（broker + 客户端同改）。
- 2026-10-31 二轮（老板反馈五条）：修复 update_fetcher 响应头缓冲 1 字节堆越界
  （Debug 断言崩溃的根因，Release 亦受影响）；指纹剔除 OS 串（补丁不改设备身份）
  + Win11 识别（build≥22000）；受管卡片隐藏 IP（ServerEntry.managed 贯通
  Config/卡片/主页位置 ComboBox，地名来自 server-list 的 remark，当前=香港）；
  后台新增「取消授权」（approved→revoked，客户端 evaluate 拦截）；黑名单三型
  （domain/ip/machine，blacklist.type 列已迁移，server 端 IP 精确匹配 + 整机
  登录即拒/心跳踢会话）。备份：.bak-20261031-2/（上一版二进制前状态）。
- 垃圾桶（2026-10-31 三轮）：后台用户面板分「在册 / 垃圾桶」双视图，拒绝与取消
  授权的记录归垃圾桶；恢复 = 新一轮试用（3 天/2GB，写死在 webadmin restore——
  broker 若改默认需同步）；彻底删除 = 抹行（设备可重新申请试用）。接口
  /api/service/users/restore|{fp}(DELETE)；SQL 在 db.py restore_trial/purge_trial。
- 编码统一（2026-10-31 四轮）：config.ini 的 GUI 侧 QSettings 读写【全部】改为
  scholini::Ini* 原语（Config.h 导出）——QSettings 写 UTF-8 与 W-API 读 ANSI 打架
  导致受管卡片名乱码（香港→棣橣离）；自建卡片中文名同病同修。红线：config.ini
  禁止再用 QSettings 读写（注册表 autostart 不受限）。受管卡片同时隐藏 IP 与
  「管理」按钮（ServerEntry.managed 贯通）。
- 位置 ComboBox 已撤销（2026-10-31 五轮，老板拍板）：受管服务器更换复用现有
  Switch 按钮（卡片只显示地名不显示 IP）；受管（第三方）仅开放 TCP——下发时
  transport=1，卡片传输下拉锁定 TCP 不可改。乱码注意：config.ini 里旧构建写入的
  坏名字在下一次列表刷新/重申请时被 IniSetStr 重写自愈；仍在的旧自建卡中文名
  改名一次即自愈。
- 机器指纹规则 v2（2026-10-31 六轮）：fp = SHA-256(salt | MachineGuid/machine-id)，
  CPU/RAM/MAC/OS 仅作展示不参与（v1 混入导致同一台机器会漂移）；注册表路径转义
  曾被写入脚本时吃掉一层（SOFTWARE\Microsoft 变 SOFTWAREMicrosoft → rc=2），
  修复后探针验证 rc=0。老 fp 记录作废（当前仅测试数据）。截断字段悬停看全部
  （webadmin 表格 title + 设置页 tooltip）。
- Debug 崩溃二轮定性（2026-10-31）：AppBridge 的分步堆自检诊断脚手架
  （全堆遍历宏 + check 线程内自检）在多线程下产生竞态误报——服务功能上线后
  后台线程变多变忙，误报从偶发变频繁（_acrt_first_block == header）。
  已整体移除（AppBridge.cpp 内留有历史说明）；若移除后仍崩，才是真堆损坏，
  走 Application Verifier + 页堆定位。
- 空设备标识守卫（2026-10-31 七轮）：MachineGuid 读取失败时指纹返回空
  （broker 400 拒绝、客户端报错），绝不退化为固定常量——否则所有读失败的
  机器共用同一个假身份（v2 转义事故期间曾短暂如此）。
- 限频事件（2026-10-31）：老板测试触发同 IP 防刷限频（3/24h）——限频日志
  register_ip_log 与 trials 是分开的，清 trials 不清限频会一直 429（已清）。
  broker 新增运维命令 clear-iplog（--ip 可选）；客户端把 429/403/404 翻译成
  人话（申请过于频繁/设备未登记/尚未申请试用）。
- server-list 公钥误填事故（2026-11-01）：重签地名时 --pubkey 误用 broker 的
  release_pub.pem（服务签名钥）而非 vpn-server 的 server_sig.pub → 客户端验签
  失败卡连接中。已重签纠正。⚠️ 铁律：server-list 的 pubkey 必须来自
  server/keys/server_sig.pub 转 SPKI DER base64；broker 的 service key 只签
  列表本身，绝不进 pubkey 字段。「刷新状态」现同时重拉服务器列表（服务方
  改钥/改址后客户端一键跟进）。
- P3 DNS 分流已实现（2026-11-01，自建分流模式生效；受管连接强制全局不受影响）：
  src/DnsProxy.{h,cpp}（127.0.0.1:53 双上游按域名分流，域名表
  docs/routing/chn-domains.txt ~11 万条，来自 dnsmasq-china-list）；TUN DNS 指向
  127.0.0.1，启动失败回落原 DNS；断线/停止即停。实测验证：审计表已抓到真实
  SNI（谷歌系域名），隧道/转发/NAT 全通。DnsProxy 有个 listSock/listenSock
  拼写教训（声明 listenSock 用 listSock → C2065，已修）。
- 受管连接恢复智能分流（2026-11-01 七轮）：P3 DNS 代理已解决国内 DNS 污染，
  受管连接不再强制全局——分流下国内直连（不烧 2GB 配额）、国外走隧道（无污染）。
  m_activeManaged 成员已移除。带宽权衡已告知老板。
- 数据面提速（2026-11-01）：send_work 预算 64→256、UDP 收包预算 64→256、
  整机黑名单检查移出逐包热路径（心跳 30s 兜底）。已重编部署（重启时 0 在线）。
  服务器出口实测 42MB/s（Cloudflare 测速），瓶颈不在服务器带宽。
- 受管传输改回 UDP（2026-11-01 八轮，老板拍板推翻「仅开放 TCP」）：下发
  transport=0（UDP），卡片传输下拉解锁（UDP 默认 / TCP 兜底可切）。速度诉求
  （TCP-over-TCP 惩罚）压过防丢包考虑；服务器本就 --transport both 双栈监听。
- P3 部署事故修复（2026-11-01）：域名表加载路径写错（cfg_app_dir=APPDATA，
  应为 get_exe_dir=exe 同目录，与 chnroute 同位）→ 代理静默不启动 → 回落国内
  DNS → 谷歌超时。已修（cfg_from_utf8(get_exe_dir())）；iss 打包同时补上
  chnroute.txt/chn-domains.txt（此前 chnroute 从未进安装包——装机版分流一直
  静默回退全局，属既有缺口）。日志自证：启动后应出现
  [DnsProxy] 已启动（域名表 109455 条）。
- 受管传输回退 TCP（2026-11-01 八轮末）：老板实测 UDP 下数据面全死（服务器
  used_bytes 冻结、vpn0 零流量——移动国际 UDP 被 QoS，握手通数据死）。已回退
  transport=1；卡片下拉保留 UDP/TCP 自选（网络支持 UDP 的用户可自试）。
  教训：「仅开放 TCP」的原始决定对移动网络是对的。
- 受管服务端到端活体测试（待老板验证）：重新申请试用即登记 v2 指纹
  （239e0a1e... 为老板机器当前指纹），此后恒定。：重新申请试用即登记 v2 指纹
  （239e0a1e... 为老板机器当前指纹），此后恒定。：客户端申请试用 → 后台「用户」面板可见 →
  转正式或试用连接 → 主页用量条走动 → 后台改配额/拒绝后的阻断表现。

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
