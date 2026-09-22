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
// 事件接线：安装/启动时应用一次；设置变化/popup 消息时重新应用
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  applyProxy();
});
chrome.runtime.onStartup.addListener(() => {
  applyProxy();
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

// service worker 冷启动时也同步一次（浏览器重启后设置可能已被清空）
applyProxy();
