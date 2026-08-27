// ============================================================
// 银狐拦截系统 - AI 外链沙箱防追踪探测模块（v2.7.0 自 background.js 抽取）
// ============================================================
// 职责：对可疑形态外链做防追踪探测——跟随重定向取最终落点、不读响应体、
//       不带 Cookie（credentials: omit）、不发 Referer、禁缓存，8 秒超时；
//       注册域级缓存与并发去重（AI 常给同站多路径链接，按注册域只探一次）
// 加载：background.js 顶部 importScripts('modules/core.js', 'modules/sandbox-probe.js')
//       ——依赖 core.js 先加载（getRegistrableDomain）；经典脚本环境，
//       禁用 import/export 语句
// 消费：globalThis.__YH_SANDBOX__.sandboxProbeUrl(url)
//       → Promise<{ ok: true, status, finalUrl } | { ok: false, error }>
(function(global) {
  'use strict';

  const CORE = global.__YH_CORE__;

  // 单请求超时（原 background.js AI_LINK_PROBE_TIMEOUT_MS）
  const AI_LINK_PROBE_TIMEOUT_MS = 8000;
  // 探测结论缓存：与 verdict 结论缓存同为 30 分钟 TTL、上限 300
  //（原与 verdict 缓存共用 AI_LINK_CACHE_* 常量，模块化后自持，语义不变）
  const PROBE_CACHE_TTL_MS = 30 * 60 * 1000;
  const PROBE_CACHE_MAX = 300;

  // v2.3.6：域名级去重——AI 常给同站多路径链接（xxx.com/dl、xxx.com/about），
  // 按完整 URL 探测会对同一主机重复发请求。探测结论按注册域缓存/去重：
  // 同域第二跳直接复用首跳结果（重定向落点核对同样以注册域为粒度，
  // 同域不同路径的重定向行为差异对风险判定无意义）。并发请求共享同一
  // in-flight Promise
  const _probeCache = new Map();     // registrable → { probe, ts }
  const _probeInFlight = new Map();  // registrable → Promise<probe>

  // ===== v2.7.2：防 SSRF —— 内网/回环/保留地址阻断（沙箱安全强化） =====
  // 恶意目标站可 302 到内网/本机服务，利用扩展把 SW 当内网探测器。对
  // 「初始 URL 字面量 IP」与「DNS 解析 IP」两路做保留段校验，命中即拒绝
  // 发出请求；探测后对最终落点再做一遍回环/内网校验兜底。
  // IPv4 保留段：0/8、10/8、100.64/10、127/8、169.254/16、172.16/12、
  // 192.168/16、192.0.2/24、224/4 等
  const PRIVATE_V4_RANGES = [
    [0, 8], [10, 8], [127, 8], [169, 9], [172, 4], [192, 7],
    [192, 8], [198, 2], [203, 1], [224, 1], [240, 1], [100, 6]
  ];
  function ipv4ToBits(ip) {
    const m = String(ip || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return -1;
    const p = [+m[1], +m[2], +m[3], +m[4]];
    if (p.some(function(n) { return n > 255; })) return -1;
    return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  }
  function isPrivateIpv4(ip) {
    const bits = ipv4ToBits(ip);
    if (bits === -1) return false;
    for (let i = 0; i < PRIVATE_V4_RANGES.length; i++) {
      const addr = PRIVATE_V4_RANGES[i][0], len = PRIVATE_V4_RANGES[i][1];
      const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
      if ((bits & mask) === ((addr * 16777216) & mask)) return true;
    }
    return false;
  }
  function isIpv4Literal(host) {
    return ipv4ToBits(String(host).replace(/\[/g, '').replace(/\]/g, '')) !== -1;
  }
  function isReservedHostLiteral(host) {
    if (!host) return false;
    host = String(host).toLowerCase().replace(/\[|\]/g, '');
    if (host === 'localhost' || host.endsWith('.localhost')) return true;
    if (host === '::1' || host === '0:0:0:0:0:0:0:1') return true;
    if (/^(fe80|fe9|fea|feb|fc|fd)/.test(host)) return true;
    if (isIpv4Literal(host) && isPrivateIpv4(host)) return true;
    return false;
  }
  function hasUserInfo(url) {
    try { const u = new URL(url); return !!(u.username || u.password); } catch(e) { return false; }
  }
  // DNS-over-HTTPS 解析 host（A 记录），返回 IP 数组；查询失败返回 null
  async function resolveHostIps(host, signal) {
    try {
      const cs = new AbortController();
      const tim = setTimeout(function() { cs.abort(); }, 4000);
      const r = await fetch('https://dns.google/resolve?name=' +
        encodeURIComponent(host) + '&type=A', { signal: cs.signal });
      clearTimeout(tim);
      if (!r.ok) return null;
      const j = await r.json();
      if (Array.isArray(j && j.Answer)) {
        return j.Answer.filter(function(a) { return a && a.type === 1 && a.data; })
          .map(function(a) { return a.data; });
      }
      return [];
    } catch(e) { return null; }
  }

  async function sandboxProbeUrl(url) {
    let registrable = '';
    try {
      const u = new URL(url);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { ok: false, error: '非网页协议' };
      }
      registrable = CORE.getRegistrableDomain(u.hostname.toLowerCase()) ||
        u.hostname.toLowerCase();
    } catch(e) { return { ok: false, error: '无法解析的地址' }; }

    const hit = _probeCache.get(registrable);
    if (hit) {
      if (Date.now() - hit.ts <= PROBE_CACHE_TTL_MS) return hit.probe;
      _probeCache.delete(registrable);
    }
    const inFlight = _probeInFlight.get(registrable);
    if (inFlight) return inFlight;

    const p = doSandboxProbe(url).then(function(probe) {
      _probeCache.set(registrable, { probe: probe, ts: Date.now() });
      if (_probeCache.size > PROBE_CACHE_MAX) {
        _probeCache.delete(_probeCache.keys().next().value);
      }
      _probeInFlight.delete(registrable);
      return probe;
    }).catch(function() {
      _probeInFlight.delete(registrable);
      return { ok: false, error: '网络错误' };
    });
    _probeInFlight.set(registrable, p);
    return p;
  }

  // 沙箱防追踪探测本体：校验目标安全 → 解析 IP 排除内网 → 跟随重定向取最终
  // 落点（不读响应体），8 秒总超时
  async function doSandboxProbe(url) {
    try {
      const pri = new URL(url);
      if (pri.protocol !== 'http:' && pri.protocol !== 'https:') {
        return { ok: false, error: '非网页协议' };
      }
      if (hasUserInfo(url)) return { ok: false, error: 'URL 含用户凭据，已拒绝探测' };
      const priHost = pri.hostname.toLowerCase().replace(/\[|\]/g, '');
      // ---- SSRF 防线①：字面量内网/回环/保留地址直接拒绝（不发出请求）----
      if (isReservedHostLiteral(priHost)) {
        return { ok: false, error: '内网/回环/保留地址，已拒绝探测（疑似 SSRF）' };
      }
      // ---- SSRF 防线②：DNS 预解析，命中保留段即拒绝 ----
      const ips = await resolveHostIps(priHost);
      if (ips && ips.some(function(ip) {
        return isIpv4Literal(ip) && isPrivateIpv4(ip);
      })) {
        return { ok: false, error: '该域名解析至内网/保留地址，已拒绝探测（疑似 SSRF）' };
      }

      const controller = new AbortController();
      const timer = setTimeout(function() { controller.abort(); }, AI_LINK_PROBE_TIMEOUT_MS);
      try {
        const resp = await fetch(url, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
          redirect: 'follow',
          referrerPolicy: 'no-referrer',
          headers: { 'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5' },
          signal: controller.signal
        });
        const finalHost = (function() { try { return new URL(resp.url || url).hostname.toLowerCase(); } catch(e) { return ''; } })();
        // ---- SSRF 防线③：最终落点回环/内网兜底（识别恶意 302）----
        if (finalHost && isReservedHostLiteral(finalHost)) {
          return { ok: false, error: '重定向至内网/回环地址，已中止探测（疑似 SSRF 攻击）' };
        }
        return { ok: true, status: resp.status, finalUrl: resp.url || url };
      } catch(e) {
        return { ok: false, error: String(e && e.name === 'AbortError' ? '超时' : '网络错误') };
      } finally {
        clearTimeout(timer);
      }
    } catch(e) {
      return { ok: false, error: e && e.message ? e.message : '无法解析的地址' };
    }
  }

  global.__YH_SANDBOX__ = global.__YH_SANDBOX__ || Object.freeze({
    sandboxProbeUrl: sandboxProbeUrl,
    // 内部判别工具（自测/回归用，带下划线表示非公开接口）
    _isPrivateIpv4: isPrivateIpv4,
    _isReservedHostLiteral: isReservedHostLiteral
  });
})(globalThis);
