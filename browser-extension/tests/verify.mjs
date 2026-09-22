// ============================================================================
// 扩展逻辑验证（Node 运行，不依赖浏览器）
//   node tests/verify.mjs
// 做法：为 chrome.* API 建桩，把 background.js 丢进 VM 执行，
// 再断言：三种模式落到 chrome.proxy 的配置是否正确、PAC 生成与域名匹配
// 是否符合预期、onAuthRequired 是否按设置回填凭据。
// ============================================================================
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import assert from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const extDir = join(here, "..");

// ---- 断言小工具 ----
let failed = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed++;
    console.error(`  ✗ ${name}\n    ${e.message}`);
  }
}

// ---- chrome API 桩 ----
function makeChrome(store) {
  const calls = { proxySet: [], proxyClear: 0, badge: [] };
  const authListeners = [];
  const errListeners = [];
  const chrome = {
    storage: {
      local: {
        async get(defaults) {
          return Object.assign({}, defaults, store);
        },
        async set(patch) {
          Object.assign(store, patch);
        }
      },
      onChanged: { addListener() {} }
    },
    proxy: {
      settings: {
        async set(arg) {
          calls.proxySet.push(arg);
        },
        async clear() {
          calls.proxyClear++;
        },
        async get() {
          return { value: { mode: "direct" } };
        }
      }
    },
    webRequest: {
      onAuthRequired: {
        addListener(fn, filter, opts) {
          authListeners.push({ fn, filter, opts });
        }
      },
      onErrorOccurred: {
        addListener(fn, filter, opts) {
          errListeners.push({ fn, filter, opts });
        }
      }
    },
    runtime: {
      getURL: (p) => "chrome-extension://test/" + p,
      onInstalled: { addListener() {} },
      onStartup: { addListener() {} },
      onMessage: { addListener() {} }
    },
    action: {
      setBadgeText(a) { calls.badge.push(a.text); },
      setBadgeBackgroundColor() {}
    }
  };
  return { chrome, calls, authListeners, errListeners };
}

// configJson：模拟扩展目录里的 config.json（不传 = 不存在，fetch 返回 404）
function loadBackground(store, configJson = null) {
  const src = readFileSync(join(extDir, "background.js"), "utf8");
  const { chrome, calls, authListeners, errListeners } = makeChrome(store);
  const fetchStub = async () =>
    configJson
      ? { ok: true, json: async () => configJson }
      : { ok: false, json: async () => ({}) };
  const ctx = vm.createContext({ chrome, console, setTimeout, clearTimeout, fetch: fetchStub });
  vm.runInContext(src, ctx);
  return { ctx, calls, authListeners, errListeners };
}

// ---- 测试 1：manifest 合法性 ----
console.log("manifest.json");
const manifest = JSON.parse(readFileSync(join(extDir, "manifest.json"), "utf8"));
check("manifest_version = 3", () => assert.equal(manifest.manifest_version, 3));
check("具备 proxy/storage 权限", () => {
  for (const p of ["proxy", "storage"]) assert.ok(manifest.permissions.includes(p), `缺 ${p}`);
});
check("具备代理认证所需权限", () => {
  for (const p of ["webRequest", "webRequestAuthProvider"])
    assert.ok(manifest.permissions.includes(p), `缺 ${p}`);
});
check("声明了 service worker 与 popup", () => {
  assert.equal(manifest.background.service_worker, "background.js");
  assert.equal(manifest.action.default_popup, "popup.html");
});

// ---- 测试 2：未启用 → 清除代理 ----
console.log("未启用状态");
{
  const store = { enabled: false, host: "1.2.3.4", port: 1080 };
  const { calls } = loadBackground(store);
  await new Promise((r) => setTimeout(r, 10));   // 等 applyProxy 的微任务完成
  check("未启用时调用 proxy.settings.clear", () => assert.equal(calls.proxyClear, 1));
  check("未启用时不写代理配置", () => assert.equal(calls.proxySet.length, 0));
}

// ---- 测试 3：全局模式 → fixed_servers + bypassList（分协议）----
console.log("全局模式");
{
  const cases = [
    { protocol: "socks5", port: 1080, scheme: "socks5" },
    { protocol: "http", port: 8080, scheme: "http" },
    { protocol: "https", port: 8443, scheme: "https" }   // TLS 加密路径
  ];
  for (const c of cases) {
    const store = {
      enabled: true, protocol: c.protocol, host: "vpn.example.com", port: c.port,
      mode: "global", list: ["intranet.corp"]
    };
    const { ctx, calls } = loadBackground(store);
    await new Promise((r) => setTimeout(r, 10));
    check(`协议 ${c.protocol} → fixed_servers(${c.scheme})`, () => {
      assert.equal(calls.proxySet.length, 1);
      const v = calls.proxySet[0].value;
      assert.equal(v.mode, "fixed_servers");
      assert.deepEqual(v.rules.singleProxy,
        { scheme: c.scheme, host: "vpn.example.com", port: c.port });
      assert.deepEqual(v.rules.bypassList, ["intranet.corp"]);
    });
    check(`协议 ${c.protocol}：PAC 生成函数可导出`, () => assert.equal(typeof ctx.buildPac, "function"));
  }
  // 未指定协议时默认 https（加密优先）
  {
    const store = { enabled: true, host: "vpn.example.com", port: 8443, mode: "global", list: [] };
    const { calls } = loadBackground(store);
    await new Promise((r) => setTimeout(r, 10));
    check("缺省协议按 https（TLS）处理", () => {
      assert.equal(calls.proxySet[0].value.rules.singleProxy.scheme, "https");
    });
  }
}

// ---- 测试 4：仅列表模式 → PAC 脚本行为 ----
console.log("仅列表模式（PAC）");
{
  const store = {
    enabled: true, protocol: "https", host: "vpn.example.com", port: 8443,
    mode: "whitelist", list: ["example.com", "*.google.com"]
  };
  const { ctx, calls } = loadBackground(store);
  await new Promise((r) => setTimeout(r, 10));
  const pac = calls.proxySet[0].value.pacScript.data;
  check("写入 pac_script 模式", () => assert.equal(calls.proxySet[0].value.mode, "pac_script"));
  check("PAC 使用 HTTPS（TLS）方案", () => assert.ok(pac.includes("HTTPS vpn.example.com:8443")));

  // 在独立上下文里执行 PAC（模拟浏览器 PAC 引擎）
  const pacCtx = vm.createContext({});
  vm.runInContext(pac, pacCtx);
  const f = pacCtx.FindProxyForURL;
  check("列表内域名走代理", () => {
    assert.equal(f("http://example.com/", "example.com"), "HTTPS vpn.example.com:8443");
    assert.equal(f("http://a.b.example.com/", "a.b.example.com"), "HTTPS vpn.example.com:8443");
  });
  check("子域后缀匹配（*.google.com）", () => {
    assert.equal(f("http://mail.google.com/", "mail.google.com"), "HTTPS vpn.example.com:8443");
  });
  check("列表外域名直连", () => {
    assert.equal(f("http://other.com/", "other.com"), "DIRECT");
  });
  check("后缀边界不误伤（notexample.com）", () => {
    assert.equal(f("http://notexample.com/", "notexample.com"), "DIRECT");
  });
  check("大写域名归一小写后匹配", () => {
    assert.equal(f("http://EXAMPLE.COM/", "EXAMPLE.COM"), "HTTPS vpn.example.com:8443");
  });
}

// ---- 测试 5：onAuthRequired 回填凭据 ----
console.log("SOCKS5 认证回调");
{
  const store = { enabled: true, protocol: "https", host: "1.2.3.4", port: 8443, user: "alice", pass: "s3cret" };
  const { authListeners } = loadBackground(store);
  check("注册了 asyncBlocking 认证监听", () => {
    assert.equal(authListeners.length, 1);
    assert.deepEqual(authListeners[0].opts, ["asyncBlocking"]);
  });
  const got = await new Promise((resolve) => {
    authListeners[0].fn({ isProxy: true, url: "https://x.com" }, resolve);
  });
  check("代理认证返回用户名/密码", () => {
    assert.deepEqual(got, { authCredentials: { username: "alice", password: "s3cret" } });
  });
  const gotNonProxy = await new Promise((resolve) => {
    authListeners[0].fn({ isProxy: false, url: "https://x.com" }, resolve);
  });
  check("非代理认证不回填凭据", () => assert.deepEqual(gotNonProxy, {}));
}

// ---- 测试 6：webRequest 错误捕获（弹窗诊断用）----
console.log("网络错误诊断记录");
{
  const store = { enabled: true, protocol: "https", host: "1.2.3.4", port: 8443 };
  const { errListeners } = loadBackground(store);
  check("注册了 onErrorOccurred 监听", () => assert.equal(errListeners.length, 1));
  errListeners[0].fn({ url: "https://api.ipify.org/?x=1", error: "net::ERR_PROXY_CERTIFICATE_INVALID" });
  await new Promise((r) => setTimeout(r, 10));
  check("检测请求的错误被记录", () => {
    assert.equal(store.lastNetError.error, "net::ERR_PROXY_CERTIFICATE_INVALID");
  });
  errListeners[0].fn({ url: "https://unrelated.example/x", error: "net::ERR_FAILED" });
  await new Promise((r) => setTimeout(r, 10));
  check("无关请求的错误不覆盖记录", () => {
    assert.equal(store.lastNetError.error, "net::ERR_PROXY_CERTIFICATE_INVALID");
  });
}

// ---- 测试 7：config.json 无人值守配置 ----
console.log("config.json 自动配置");
{
  // applyOnStartup：强制启用并应用（无论之前存过什么）
  const store = { enabled: false, host: "old.example", port: 1 };
  const cfg = {
    applyOnStartup: true, enabled: true, protocol: "https",
    host: "154.36.166.113", port: 8443, user: "alice", pass: "123",
    mode: "global", list: []
  };
  const { calls } = loadBackground(store, cfg);
  await new Promise((r) => setTimeout(r, 20));
  check("config 覆盖 storage 的既有值", () => {
    assert.equal(store.host, "154.36.166.113");
    assert.equal(store.enabled, true);
    assert.equal(store.user, "alice");
  });
  check("config 生效后写入 HTTPS 代理", () => {
    const v = calls.proxySet[calls.proxySet.length - 1].value;
    assert.deepEqual(v.rules.singleProxy,
      { scheme: "https", host: "154.36.166.113", port: 8443 });
  });

  // applyOnce：仅首次（storage 无 enabled）生效
  const used = { enabled: false, host: "keep.example" };
  loadBackground(used, { applyOnce: true, enabled: true, host: "new.example", port: 1 });
  await new Promise((r) => setTimeout(r, 20));
  check("applyOnce 不覆盖已有设置", () => assert.equal(used.host, "keep.example"));

  // 没有 config.json：不应报错，也不改 storage
  const plain = { enabled: true, protocol: "socks5", host: "1.1.1.1", port: 1080 };
  const r = loadBackground(plain, null);
  await new Promise((r2) => setTimeout(r2, 20));
  check("无 config.json 时按 storage 正常工作", () => {
    assert.equal(plain.host, "1.1.1.1");
    assert.equal(r.calls.proxySet[0].value.rules.singleProxy.scheme, "socks5");
  });
}

console.log(failed === 0 ? "\n全部通过" : `\n${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
