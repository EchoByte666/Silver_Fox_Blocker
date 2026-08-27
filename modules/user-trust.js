// 银狐拦截系统 - 用户信任记忆模块（v2.7.1 自 background.js 抽取）
// 职责：host 级人工放行信号——用户确认过解冻/继续访问的站点在 TTL 内获得
//       评分抵扣与软拦截免冻结。storage.local 持久化（SW 重启不丢），
//       惰性加载 + 防抖写回 + 容量上限。防滥用边界：黑名单/强特征/DNR
//       拦截层永不读取本表（由调用方保证）
// 导出：__YH_USER_TRUST__ = { ensureUserTrustLoaded, markUserTrusted,
//       isUserTrustedActive, USER_TRUST_TTL_MS, USER_TRUST_DISCOUNT }
(function(global) {
'use strict';

// ===== v2.6.0 用户信任记忆（host 级人工放行信号，storage.local 持久化） =====
// 消费点有两处（语义保持一致）：
//   1. scorePage 同步决策：评分抵扣 USER_TRUST_DISCOUNT 分 + 软拦截不冻结；
//   2. enhanceScoreAsync 对账：警示层冻结指令对信任 host 关闭。
// 防滥用边界：黑名单命中 / noah/adseo 强特征 / DNR 拦截层完全不读取信任表，
// 白名单仍是唯一全量放行通道；7 天自动过期防陈旧误信
const USER_TRUST_STORAGE_KEY = 'yhUserTrustMap';
const USER_TRUST_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const USER_TRUST_MAX_ENTRIES = 500;
const USER_TRUST_DISCOUNT = 20;

let _userTrustMap = null;        // hostname → 登记时间戳（惰性加载）
let _userTrustSaveTimer = null;  // 写入防抖句柄

// 惰性加载信任表：SW 每次唤醒后首次访问时从 storage.local 灌回，
// 过期条目在加载阶段即丢弃；读取失败安全降级为空表（仅失去抵扣，无副作用）
function ensureUserTrustLoaded() {
  if (_userTrustMap) return Promise.resolve(_userTrustMap);
  return new Promise(function(resolve) {
    let settled = false;
    const finish = function(map) {
      if (!settled) { settled = true; _userTrustMap = map; resolve(map); }
    };
    try {
      chrome.storage.local.get(USER_TRUST_STORAGE_KEY, function(data) {
        const map = new Map();
        try {
          const raw = data && data[USER_TRUST_STORAGE_KEY];
          if (raw && typeof raw === 'object') {
            for (const host of Object.keys(raw)) {
              const ts = Number(raw[host]);
              if (host && ts > 0 && Date.now() - ts < USER_TRUST_TTL_MS) map.set(host, ts);
            }
          }
        } catch(e) { /* 记录损坏视为空表 */ }
        finish(map);
      });
    } catch(e) { finish(new Map()); }
  });
}

// 防抖合并写回（一批决策只落盘一次）
function persistUserTrustSoon() {
  if (_userTrustSaveTimer) return;
  _userTrustSaveTimer = setTimeout(function() {
    _userTrustSaveTimer = null;
    if (!_userTrustMap) return;
    try {
      const record = {};
      for (const [host, ts] of _userTrustMap) record[host] = ts;
      chrome.storage.local.set(
        { [USER_TRUST_STORAGE_KEY]: record },
        function() { void chrome.runtime.lastError; });
    } catch(e) { /* */ }
  }, 800);
}

// 登记 host 为"用户信任"（传入 hostname 或完整 URL 均可）
function markUserTrusted(urlOrHostname) {
  let host = String(urlOrHostname || '').toLowerCase().trim();
  if (!host) return;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(host)) {
    try { host = new URL(host).hostname.toLowerCase(); } catch(e) { return; }
  }
  if (!host || host.indexOf('.') === -1 || /\s/.test(host)) return;
  if (!_userTrustMap) {
    ensureUserTrustLoaded().then(function() { markUserTrusted(host); });
    return;
  }
  if (_userTrustMap.size >= USER_TRUST_MAX_ENTRIES && !_userTrustMap.has(host)) {
    const now = Date.now();
    for (const [h, ts] of _userTrustMap) {
      if (now - ts >= USER_TRUST_TTL_MS) _userTrustMap.delete(h);
    }
    if (_userTrustMap.size >= USER_TRUST_MAX_ENTRIES) {
      let oldestHost = null, oldestTs = Infinity;
      for (const [h, ts] of _userTrustMap) {
        if (ts < oldestTs) { oldestTs = ts; oldestHost = h; }
      }
      if (oldestHost) _userTrustMap.delete(oldestHost);
    }
  }
  _userTrustMap.set(host, Date.now());
  persistUserTrustSoon();
}

// 同步查询（调用方须已 await ensureUserTrustLoaded()）
function isUserTrustedActive(hostname) {
  try {
    const host = String(hostname || '').toLowerCase();
    return !!(_userTrustMap && host && _userTrustMap.get(host) &&
      Date.now() - _userTrustMap.get(host) < USER_TRUST_TTL_MS);
  } catch(e) { return false; }
}


global.__YH_USER_TRUST__ = global.__YH_USER_TRUST__ || Object.freeze({
  ensureUserTrustLoaded: ensureUserTrustLoaded,
  markUserTrusted: markUserTrusted,
  isUserTrustedActive: isUserTrustedActive,
  USER_TRUST_TTL_MS: USER_TRUST_TTL_MS,
  USER_TRUST_DISCOUNT: USER_TRUST_DISCOUNT
});
})(globalThis);
