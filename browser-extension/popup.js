// ============================================================================
// popup：读写设置（chrome.storage.local → background 应用 chrome.proxy）
// 输入即保存（防抖 300ms），无需手动提交；开关立即生效。
// ============================================================================

const $ = (id) => document.getElementById(id);

const els = {
  enabled: $("enabled"),
  host: $("host"),
  port: $("port"),
  user: $("user"),
  pass: $("pass"),
  mode: $("mode"),
  protocol: $("protocol"),
  portLabel: $("portLabel"),
  list: $("list"),
  listLabel: $("listLabel"),
  test: $("test"),
  status: $("status")
};

const DEFAULTS = {
  enabled: false,
  // 默认 HTTPS（TLS 加密）；服务端只开了 SOCKS5 时改选 SOCKS5
  protocol: "https",
  host: "",
  port: 8443,
  user: "",
  pass: "",
  mode: "global",
  list: []
};

function setStatus(text, kind) {
  els.status.textContent = text || "";
  els.status.className = "status" + (kind ? " " + kind : "");
}

function parseList(text) {
  return text
    .split("\n")
    .map((s) => s.trim().replace(/^\*\./, ""))
    .filter((s) => s)
    .filter((s, i, a) => a.indexOf(s) === i);
}

function readForm() {
  const port = parseInt(els.port.value.trim(), 10);
  const fallbackPort = els.protocol.value === "socks5" ? 1080 : 8443;
  return {
    enabled: els.enabled.checked,
    protocol: els.protocol.value,
    host: els.host.value.trim(),
    port: Number.isFinite(port) && port > 0 && port <= 65535 ? port : fallbackPort,
    user: els.user.value.trim(),
    pass: els.pass.value,
    mode: els.mode.value,
    list: parseList(els.list.value)
  };
}

function writeForm(s) {
  els.enabled.checked = !!s.enabled;
  els.protocol.value = s.protocol || "https";
  els.host.value = s.host || "";
  els.port.value = s.port || (els.protocol.value === "socks5" ? 1080 : 8443);
  els.user.value = s.user || "";
  els.pass.value = s.pass || "";
  els.mode.value = s.mode || "global";
  els.list.value = (s.list || []).join("\n");
  updateListLabel();
}

function updateListLabel() {
  els.listLabel.textContent = els.mode.value === "whitelist"
    ? "代理域名列表（每行一个）"
    : "直连例外域名列表（每行一个，可留空）";
}

// 输入即保存（防抖）：变化 → storage → background.applyProxy
let saveTimer = null;
function scheduleSave() {
  setStatus("保存中…");
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const s = readForm();
    await chrome.storage.local.set(s);
    const { lastError } = await chrome.storage.local.get({ lastError: "" });
    if (lastError) {
      setStatus("应用失败: " + lastError, "err");
    } else if (s.enabled && !s.host) {
      setStatus("请填写服务器地址", "err");
    } else {
      setStatus(s.enabled ? "已启用" : "已停用", "ok");
    }
  }, 300);
}

["host", "port", "user", "pass", "list"].forEach((k) => {
  els[k].addEventListener("input", scheduleSave);
});
els.protocol.addEventListener("change", () => {
  updatePortLabel();
  scheduleSave();
});
els.mode.addEventListener("change", () => {
  updateListLabel();
  scheduleSave();
});
els.enabled.addEventListener("change", scheduleSave);

// net::ERR_* → 中文处置建议
function hintForNetError(code) {
  if (code.indexOf("CERT") !== -1 || code.indexOf("certificate") !== -1)
    return "（证书未被信任：在客户端导入 proxy.cert.pem 后【完全退出并重开浏览器】）";
  if (code.indexOf("TIMED_OUT") !== -1 || code.indexOf("CONNECTION") !== -1 ||
      code.indexOf("REFUSED") !== -1 || code.indexOf("TUNNEL") !== -1)
    return "（代理端口不可达：确认服务端已启动该端口、云安全组/防火墙已放行）";
  if (code.indexOf("AUTH") !== -1 || code.indexOf("407") !== -1)
    return "（认证失败：用户名/密码与服务端 --proxy-user/--proxy-pass 不一致）";
  if (code.indexOf("NAME_NOT_RESOLVED") !== -1)
    return "（域名解析失败：服务器地址填错或本地 DNS 被劫持）";
  return "";
}

// 当前 chrome.proxy 的生效状态（诊断用）：direct / fixed_servers(scheme host:port) / pac
async function describeProxy() {
  try {
    const st = await chrome.proxy.settings.get({});
    const v = st && st.value ? st.value : {};
    if (v.mode === "fixed_servers" && v.rules && v.rules.singleProxy) {
      const p = v.rules.singleProxy;
      return `已生效 ${p.scheme} ${p.host}:${p.port}`;
    }
    if (v.mode === "pac_script") return "已生效 PAC";
    return "未生效（direct）";
  } catch (e) {
    return "状态未知: " + (e && e.message ? e.message : e);
  }
}

// 检测出口 IP：请求经当前代理发出（未启用 = 本地 IP）
els.test.addEventListener("click", async () => {
  setStatus("检测中…");
  const proxy_desc = await describeProxy();
  try {
    const res = await fetch("https://api.ipify.org?format=json", { cache: "no-store" });
    const j = await res.json();
    setStatus(`出口 IP: ${j.ip || "未知"} · ${proxy_desc}`, "ok");
  } catch (e) {
    // fetch 只看得到 "Failed to fetch"；真实 net::ERR_* 由 background 从
    // webRequest.onErrorOccurred 记录，这里读出来并给出对应处置建议
    let detail = e && e.message ? e.message : String(e);
    try {
      const { lastNetError } = await chrome.storage.local.get({ lastNetError: null });
      if (lastNetError && Date.now() - lastNetError.ts < 10_000 && lastNetError.error) {
        detail = lastNetError.error + hintForNetError(lastNetError.error);
      }
    } catch (_) { /* 读不到就用兜底文案 */ }
    setStatus(`检测失败: ${detail} · ${proxy_desc}`, "err");
  }
});

// 初始化
(async () => {
  const s = await chrome.storage.local.get(DEFAULTS);
  writeForm(s);
  if (s.enabled && s.host) {
    setStatus(await describeProxy(), "ok");
  } else {
    setStatus("未启用（右上角开关关闭）");
  }
})();
