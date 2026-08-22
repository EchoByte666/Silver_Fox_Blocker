// 银狐拦截系统 - Offscreen 文档
// 加载后自动获取远程规则，结果写入 storage
//（background 通过 storage.onChanged 感知结果，等待上限 15 秒）

// 单个规则源请求超时（毫秒）
const FETCH_TIMEOUT = 10000;

// 远程规则源列表（按优先级依次尝试）。
// 注意：background.js 与 popup.js 中有相同列表，修改时需三处同步。
// v2.1.1：移除 http://anti-silverfox.wpidc.top 明文源（HTTP 链路可被
// 中间人篡改规则内容；HTTPS 源 + 内置规则兜底已覆盖其作用）
const URLS = [
  'https://deepformat.top/yh/fake.txt',
  'https://fyh.johnnyblog.top/fake.txt',
  'https://dfcloud.qzz.io/f/MJTE/fake.txt',
  'https://rvit.top/fake.txt',
  'https://cloud.mcnan.top/fake.txt',
  'https://sysbbs.cn/fake.txt'
];

// 解析规则文本：逐行小写化，过滤空行与注释行，要求含点号（形如域名）
function parseDomains(text) {
  return text.split('\n')
    .map(function(l) { return l.trim().toLowerCase(); })
    .filter(function(l) { return l.length > 0 && !l.startsWith('#') && !l.startsWith('//') && l.includes('.'); });
}

// 带超时的 fetch（AbortController 实现）
function doFetch(url) {
  return new Promise(function(resolve, reject) {
    const ctrl = new AbortController();
    const timer = setTimeout(function() { ctrl.abort(); }, FETCH_TIMEOUT);
    fetch(url, { signal: ctrl.signal, cache: 'no-store' })
      .then(function(r) { clearTimeout(timer); return r; })
      .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
      .then(function(t) { if (t && t.trim()) resolve(t); else reject(new Error('empty')); })
      .catch(function(e) { clearTimeout(timer); reject(e); });
  });
}

// fetch 被 CSP/网络策略拒绝时的 XHR 兜底通道
function tryXHR(url) {
  return new Promise(function(resolve, reject) {
    const xhr = new XMLHttpRequest();
    xhr.timeout = FETCH_TIMEOUT;
    xhr.onload = function() { if (xhr.status === 200) resolve(xhr.responseText); else reject(); };
    xhr.onerror = reject;
    xhr.ontimeout = reject;
    xhr.open('GET', url);
    xhr.send();
  });
}

// 向 background 回执拉取结果（fetchViaOffscreen 通过 runtime 消息监听，
// 不依赖 storage.onChanged——规则内容未变时 storage 不触发事件）
function replyResult(ok, domains) {
  try {
    chrome.runtime.sendMessage(
      { action: 'offscreenResult', ok: ok, domains: domains || [] },
      function() { void chrome.runtime.lastError; }
    );
  } catch(e) { /* */ }
}

(async function() {
  // 依次尝试各规则源：fetch 失败自动降级 XHR，任一成功即写入 storage
  for (let i = 0; i < URLS.length; i++) {
    try {
      const text = await doFetch(URLS[i]).catch(function() { return tryXHR(URLS[i]); });
      if (!text) continue;
      const domains = parseDomains(text);
      if (domains.length > 0) {
        try {
          await chrome.storage.local.set({
            blocklist: domains, lastRefresh: Date.now(), lastRefreshStatus: 'remote'
          });
        } catch(e) { /* storage 可能未就绪 */ }
        replyResult(true, domains);
        return;
      }
    } catch(e) { /* 试下一个 */ }
  }
  // 全部失败：不动 blocklist（让 background 走内置兜底），只写状态字段并回执失败
  try {
    await chrome.storage.local.set({ lastRefresh: Date.now(), lastRefreshStatus: 'offscreen_all_failed' });
  } catch(e) { /* */ }
  replyResult(false);
})();
