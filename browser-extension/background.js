// ============================================================================
// ScholarVPN 浏览器代理 —— MV3 service worker
//
// 职责：把"是否启用 / 服务器地址 / 代理范围"落到 chrome.proxy 设置上。
//   - 全局模式：fixed_servers + singleProxy(socks5)，列表作为例外直连（bypassList）
//   - 仅列表模式：pac_script，只有列表内域名走代理
//   - 认证：SOCKS5 用户名/密码在 webRequest.onAuthRequired 里现取现填
//     （凭据只存在 chrome.storage.local，不会写进 PAC/fixed_servers 配置）
//
// 只在浏览器内生效：不影响系统网络设置与其他应用。
// ============================================================================

const DEFAULT_STATE = {
  enabled: false,
  // 代理协议：https = TLS 加密（推荐） / socks5 = 明文标准协议 / http = 明文
  protocol: "https",
  host: "",
  port: 8443,
  user: "",
  pass: "",
  // global = 全部走代理（列表=直连例外）；whitelist = 只有列表走代理
  mode: "global",
  list: []
};

const PROXY_AUTH_REALM = "ScholarVPN";

// ---------------------------------------------------------------------------
// 状态读写
// ---------------------------------------------------------------------------
async function getState() {
  const s = await chrome.storage.local.get(DEFAULT_STATE);
  return Object.assign({}, DEFAULT_STATE, s);
}

async function setState(patch) {
  await chrome.storage.local.set(patch);
}

// 列表项归一化：去空白 / 去 "*.", 前缀 / 转小写（"*.google.com" 与
// "google.com" 等价：hostMatches 已含子域后缀匹配，通配前缀只是书写习惯）
function normalizeList(list) {
  return (list || [])
    .map((d) => String(d).trim().toLowerCase().replace(/^\*\./, ""))
    .filter((d) => d)
    .filter((d, i, a) => a.indexOf(d) === i);
}

// 协议 → PAC/固定代理里的方案名
function schemeOf(state) {
  if (state.protocol === "socks5")
    return "SOCKS5";
  if (state.protocol === "http")
    return "HTTP";
  return "HTTPS";          // 默认：TLS 加密的 HTTP 代理
}

// 生成 PAC 脚本（列表模式下使用）。域名匹配：精确 + 子域后缀。
function buildPac(state) {
  const list = normalizeList(state.list);
  const proxy = `${schemeOf(state)} ${state.host}:${state.port}`;
  const quoted = list.map((d) => JSON.stringify(d)).join(", ");
  return `
var PROXY = ${JSON.stringify(proxy)};
var DIRECT = "DIRECT";
var LIST = [${quoted}];
function hostMatches(host, domain) {
  return host === domain || (host.length > domain.length &&
    host.lastIndexOf(domain) === host.length - domain.length &&
    host[host.length - domain.length - 1] === ".");
}
function FindProxyForURL(url, host) {
  host = (host || "").toLowerCase();
  for (var i = 0; i < LIST.length; i++) {
    if (hostMatches(host, LIST[i])) return PROXY;
  }
  return DIRECT;
}
`;
}

// ---------------------------------------------------------------------------
// 可选 config.json（放在扩展目录内）——无人值守部署用
//   { "applyOnStartup": true,  // 每次浏览器启动都把下面配置写回并生效
//     "applyOnce": true,       // 或：仅在从未保存过设置时应用一次
//     "enabled": true, "protocol": "https", "host": "1.2.3.4", "port": 8443,
//     "user": "alice", "pass": "...", "mode": "global", "list": [] }
// 说明：applyOnStartup 适合固定部署（避免误关）；日常手动控制删掉该文件即可
// ---------------------------------------------------------------------------
const CONFIG_KEYS = ["enabled", "protocol", "host", "port", "user", "pass", "mode", "list"];

async function applyConfigFile() {
  let cfg = null;
  let status = -1;
  let err = "";
  try {
    const res = await fetch(chrome.runtime.getURL("config.json"), { cache: "no-store" });
    status = res.status;
    if (!res.ok) {
      await writeDiag({ configStatus: status, note: "config.json 不存在或不可读" });
      return false;
    }
    cfg = await res.json();
  } catch (e) {
    err = String(e && e.message ? e.message : e);
    await writeDiag({ configStatus: status, note: "fetch 异常", err });
    return false;                     // 没有 config.json = 正常情况
  }
  if (!cfg || typeof cfg !== "object")
    return false;

  const stored = await chrome.storage.local.get(["enabled"]);
  const firstRun = stored.enabled === undefined;
  if (!(cfg.applyOnStartup === true || (cfg.applyOnce === true && firstRun))) {
    await writeDiag({ configStatus: status, note: "config 存在但未开启 applyOnStartup",
                      applyOnStartup: cfg.applyOnStartup === true, firstRun });
    return false;
  }

  const patch = {};
  for (const k of CONFIG_KEYS) {
    if (cfg[k] !== undefined)
      patch[k] = cfg[k];
  }
  if (Object.keys(patch).length === 0)
    return false;
  await chrome.storage.local.set(patch);
  await writeDiag({ configStatus: status, note: "已应用 config.json", applied: true });
  console.log("[ScholarVPN] 已应用 config.json 配置");
  return true;
}

// 启动诊断落盘：SW 是否运行、config.json 读取结果（外部可读，便于无人值守排障）
async function writeDiag(extra) {
  try {
    const stored = await chrome.storage.local.get({ diag: {} });
    await chrome.storage.local.set({
      diag: Object.assign({}, stored.diag, extra, { ts: Date.now(), sw: true })
    });
  } catch (_) { /* 诊断失败不影响主流程 */ }
}

// ---------------------------------------------------------------------------
// 应用设置到 chrome.proxy
// ---------------------------------------------------------------------------
async function applyProxy() {
  const s = await getState();
  const enabled = s.enabled && s.host && s.port > 0;

  updateBadge(enabled);

  if (!enabled) {
    await chrome.proxy.settings.clear({ scope: "regular" });
    return;
  }

  try {
    if (s.mode === "whitelist") {
      await chrome.proxy.settings.set({
        scope: "regular",
        value: {
          mode: "pac_script",
          pacScript: { data: buildPac(s) }
        }
      });
    } else {
      // 全局：全部走 SOCKS5；列表里的域名直连（bypassList）
      await chrome.proxy.settings.set({
        scope: "regular",
        value: {
          mode: "fixed_servers",
          rules: {
            singleProxy: {
              // chrome.proxy 方案：https = 浏览器↔代理整条链路 TLS 加密
              scheme: (s.protocol === "socks5") ? "socks5"
                    : (s.protocol === "http") ? "http" : "https",
              host: s.host,
              port: Number(s.port)
            },
            bypassList: normalizeList(s.list)
          }
        }
      });
    }
  } catch (e) {
    console.error("[ScholarVPN] 应用代理设置失败:", e);
    await chrome.storage.local.set({ lastError: String(e) });
  }
}

function updateBadge(on) {
  chrome.action.setBadgeText({ text: on ? "ON" : "" });
  chrome.action.setBadgeBackgroundColor({ color: on ? "#4CAF50" : "#9E9E9E" });
}

// ---------------------------------------------------------------------------
// SOCKS5 用户名/密码认证（RFC 1929）：由 Chrome 在代理要求认证时回调
// ---------------------------------------------------------------------------
chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!details.isProxy) {
      callback({});
      return;
    }
    getState().then((s) => {
      if (s.enabled && s.user) {
        callback({ authCredentials: { username: s.user, password: s.pass || "" } });
      } else {
        callback({});
      }
    });
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

// ---------------------------------------------------------------------------
// 网络错误捕获（诊断用）
// 弹窗里 fetch 失败只会抛 "Failed to fetch"，看不到 Chrome 的真实错误码
// （net::ERR_PROXY_CERTIFICATE_INVALID 等）——这里用 webRequest.onErrorOccurred
// 记录"检测出口 IP"那次请求的错误，供弹窗展示，便于快速定位
// ---------------------------------------------------------------------------
chrome.webRequest.onErrorOccurred.addListener(
  (d) => {
    if (!d || !d.url || d.url.indexOf("api.ipify.org") === -1)
      return;   // 只关心检测请求，避免被网页自身的错误刷屏
    chrome.storage.local.set({
      lastNetError: { error: d.error || "", url: d.url, ts: Date.now() }
    });
  },
  { urls: ["<all_urls>"] }
);

// ---------------------------------------------------------------------------
// 事件接线：安装/启动时应用一次；设置变化/popup 消息时重新应用
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  applyProxy();
});
chrome.runtime.onStartup.addListener(() => {
  // 浏览器启动：先应用可选 config.json（无人值守），再落 chrome.proxy
  applyConfigFile()
    .catch(() => {})
    .then(() => applyProxy());
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") applyProxy();
});
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "apply") {
    applyProxy().then(() => sendResponse({ ok: true }));
    return true;   // 异步响应
  }
  return false;
});

// service worker 冷启动：先应用可选 config.json（无人值守部署），再落 chrome.proxy
(async () => {
  await writeDiag({ note: "SW 已启动" });
  try {
    await applyConfigFile();
  } catch (e) {
    console.error("[ScholarVPN] config.json 应用失败:", e);
  }
  await applyProxy();
})();
