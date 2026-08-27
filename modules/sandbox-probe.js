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

  // 沙箱防追踪探测本体：跟随重定向取最终落点，不读响应体，8 秒超时
  async function doSandboxProbe(url) {
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
      return { ok: true, status: resp.status, finalUrl: resp.url || url };
    } catch(e) {
      return { ok: false, error: String(e && e.name === 'AbortError' ? '超时' : '网络错误') };
    } finally {
      clearTimeout(timer);
    }
  }

  global.__YH_SANDBOX__ = global.__YH_SANDBOX__ || Object.freeze({
    sandboxProbeUrl: sandboxProbeUrl
  });
})(globalThis);
