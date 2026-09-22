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

// 检测出口 IP：请求经当前代理发出（未启用 = 本地 IP）
els.test.addEventListener("click", async () => {
  setStatus("检测中…");
  try {
    const res = await fetch("https://api.ipify.org?format=json", { cache: "no-store" });
    const j = await res.json();
    setStatus("当前出口 IP: " + (j.ip || "未知"), "ok");
  } catch (e) {
    setStatus("检测失败（网络或代理不可达）", "err");
  }
});

// 初始化
(async () => {
  const s = await chrome.storage.local.get(DEFAULTS);
  writeForm(s);
  const st = await chrome.proxy.settings.get({});
  if (st && st.value && st.value.mode && st.value.mode !== "direct") {
    setStatus("代理已生效", "ok");
  } else if (s.enabled && s.host) {
    setStatus("已保存，等待生效", "");
  } else {
    setStatus("未启用");
  }
})();
