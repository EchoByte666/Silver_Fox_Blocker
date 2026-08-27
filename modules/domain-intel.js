// 银狐拦截系统 - 域名情报模块（v2.7.1 自 background.js 抽取）
// 职责：异步增强所需的全部外部数据源——域名年龄五通道（IANA RDAP 引导 →
//       硬编码 RDAP 表 → rdap.org 重定向器 → WhoDat → whoisjs）+ ICP 备案
//       两源（uapis/apihz，仅采信正面证据）+ 备案号序号剥离比对
// 加载：background.js importScripts（modules/core.js 先加载）；纯 fetch 模块
// 导出：__YH_DOMAIN_INTEL__ = { queryDomainAge, queryIcpRecord,
//       skipIcpQueryResult, icpNumbersMatch }
(function(global) {
'use strict';
const CORE = global.__YH_CORE__;
const debug = CORE.debug;
const getRegistrableDomain = CORE.getRegistrableDomain;

// ===== v2.1.3：RDAP 域名年龄 + ICP 备案 API 异步增强 =====
// 参考 VirusDetector 开源项目的 rdap-client.js / icp-api.js 设计，按本项目
// 架构（非 module SW、消息驱动评分）裁剪实现。
//
// 定位：scorePage 同步决策（放行/软拦截）后的第二阶段增强——新注册域名
// 是钓鱼站强特征（域名成本极低，用完即弃），页面盗用他人备案号也是
// 仿冒站常见操作。两者都无法从页面 DOM 判断，必须查外部数据源。
// 触发条件：总分 ≥60（有基础风险才值得花网络请求）且未走硬拦截路径。
// 升级规则：增强后总分 ≥150 且证据类别 ≥2 → 执行硬拦截（跳警告页）。
// 失败安全：任一数据源查询失败不影响原决策（增强只加风险分不减）。
//
// v2.1.4 多源备援扩充（全部免费、无需登录，2026-08 实测可用）：
//   域名年龄五通道：
//     A. IANA RDAP 引导文件 → 权威注册局服务器（主通道）
//     B. 硬编码常用 TLD 的 RDAP 表（IANA 不可达时）
//     C. rdap.org 通用重定向器（按 TLD 302 跳权威服务器，兜住表外 TLD）
//     D. WhoDat（who-dat.as93.net，结构化 WHOIS JSON，覆盖 .cn/.com.cn
//        等 CNNIC 无公开 RDAP 的空档——此前这些域完全放弃域龄检测）
//     E. whoisjs.com（原文 WHOIS 文本正则提取注册时间，末位兜底）
//   ICP 备案：
//     uapis.cn（HTTP 404 + code NOT_FOUND = 明确无备案结论）
//     apihz.cn 公共源（公共 ID 全网共享限频极严——限频响应同为 code 400，
//     故仅采信"code 200 且备案号合规"的正面证据，杜绝把限频误判为无备案）

const V213_DAY_MS = 24 * 60 * 60 * 1000;

// v2.7.0：getRegistrableDomain 已抽取至 modules/core.js（顶部解构引入）

// --- RDAP 客户端（精简版，v2.1.4 扩充备援）---
// 解析顺序：IANA 引导文件（TLD → RDAP 服务器映射，24h 缓存）→ 硬编码
// 常用 gTLD 回退表 → rdap.org 通用重定向器（302 跳权威服务器，实测可用，
// 兜住引导文件不可达与表外 TLD）。.cn 无公开 RDAP（IANA 引导无 cn 条目，
// rdap.org 对 .cn 实测 404），跳过 RDAP 直接走 DOMAIN_AGE_WHOIS_PROVIDERS 兜底链
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const RDAP_FALLBACK_SERVERS = {
  'com': 'https://rdap.verisign.com/com/v1/',
  'net': 'https://rdap.verisign.com/net/v1/',
  'org': 'https://rdap.publicinterestregistry.org/rdap/',
  'info': 'https://rdap.identitydigital.services/rdap/',
  'io': 'https://rdap.identitydigital.services/rdap/',
  'biz': 'https://rdap.nic.biz/',
  'tv': 'https://rdap.nic.tv/',
  'cc': 'https://tld-rdap.verisign.com/cc/v1/',
  'xyz': 'https://rdap.centralnic.com/xyz/',
  'top': 'https://rdap.zdnsgtld.com/top/',
  'co': 'https://rdap.nic.co/',
  'me': 'https://rdap.nic.me/',
  'app': 'https://pubapi.registry.google/rdap/',
  'dev': 'https://pubapi.registry.google/rdap/'
};
const NO_RDAP_TLDS = new Set(['cn']);
// v2.1.4 新增：通用 RDAP 重定向器——专用服务器查不到时的最终兜底
const RDAP_UNIVERSAL_BASE = 'https://rdap.org/';
let _rdapBootstrap = null;      // { tldToServer: Map, ts }
let _rdapBootstrapPromise = null; // 互斥：防并发重复下载引导文件
const _rdapResultCache = new Map(); // domain -> { creationDays, ts }

async function getRdapBootstrap() {
  if (_rdapBootstrap && Date.now() - _rdapBootstrap.ts < V213_DAY_MS) return _rdapBootstrap;
  if (_rdapBootstrapPromise) return _rdapBootstrapPromise;
  _rdapBootstrapPromise = (async function() {
    try {
      const controller = new AbortController();
      const timer = setTimeout(function() { controller.abort(); }, 8000);
      const resp = await fetch(RDAP_BOOTSTRAP_URL, { signal: controller.signal });
      clearTimeout(timer);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const json = await resp.json();
      const map = new Map();
      for (const entry of (json.services || [])) {
        if (!Array.isArray(entry) || entry.length < 2) continue;
        const [tlds, urls] = entry;
        if (!Array.isArray(tlds) || !Array.isArray(urls) || urls.length === 0) continue;
        const base = String(urls[0]).replace(/\/+$/, '/');
        for (const tld of tlds) {
          if (typeof tld === 'string') map.set(tld.toLowerCase(), base);
        }
      }
      _rdapBootstrap = { tldToServer: map, ts: Date.now() };
    } catch(e) {
      // IANA 不可达 → 硬编码回退表（覆盖银狐样本常用的 com/cc/top 等）
      const map = new Map(Object.entries(RDAP_FALLBACK_SERVERS));
      _rdapBootstrap = { tldToServer: map, ts: Date.now() };
    } finally {
      _rdapBootstrapPromise = null;
    }
    return _rdapBootstrap;
  })();
  return _rdapBootstrapPromise;
}

// v2.1.4 新增：RDAP 服务基址解析——IANA 引导优先；引导内无此 TLD 或
// 引导异常时回退 rdap.org 通用重定向器（fetch 自动跟随其 302 跳转）
async function resolveRdapBase(tld) {
  try {
    const boot = await getRdapBootstrap();
    const base = boot.tldToServer.get(tld);
    if (base) return base;
  } catch(e) { /* 引导异常：走通用重定向器 */ }
  return RDAP_UNIVERSAL_BASE;
}

// v2.1.4 新增：ISO 时间字符串 → 距今天数（无效输入返回 -1）
function daysSinceIso(iso) {
  if (!iso) return -1;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return -1;
  return Math.max(0, Math.floor((Date.now() - d.getTime()) / V213_DAY_MS));
}

// v2.1.4 新增：RFC 9083 RDAP JSON → 注册天数
//（events[eventAction=registration].eventDate），无注册事件返回 -1
function parseRdapCreationDays(json) {
  const reg = ((json && json.events) || []).find(function(e) {
    return e && e.eventAction === 'registration';
  });
  return reg ? daysSinceIso(reg.eventDate) : -1;
}

// --- v2.1.4 新增：WHOIS 类域龄兜底源（免费、无需登录，实测可用）---
// 定位：RDAP 主通道失败后的第二梯队，重点覆盖 .cn/.com.cn 等 CNNIC
// 无公开 RDAP 的 TLD——此前这些域名直接放弃域龄检测。解析函数返回
// 注册天数（≥0 有效）或 null（本源无结论，继续下一个源）
const DOMAIN_AGE_WHOIS_PROVIDERS = [
  {
    // WhoDat：开源 WHOIS JSON API，结构化 dates.created（ISO 8601），
    // 未注册域名返回 isRegistered:false（负样本形态明确）
    name: 'whodat',
    buildUrl: function(domain) {
      return 'https://who-dat.as93.net/' + encodeURIComponent(domain);
    },
    parse: function(data) {
      if (!data || typeof data !== 'object') return null;
      if (data.isRegistered === false) return null;   // 未注册：无域龄可算
      if (!data.isRegistered) return null;            // 字段缺失：不采信
      return data.dates ? daysSinceIso(data.dates.created) : null;
    }
  },
  {
    // whoisjs：原文 WHOIS 文本兜底。.cn 系格式为 "Registration Time:"，
    // gTLD 格式为 "Creation Date:"，两种都试（仅接受 YYYY-MM-DD 日期形态，
    // 避免误抓无关行）
    name: 'whoisjs',
    buildUrl: function(domain) {
      return 'https://whoisjs.com/api/v1/' + encodeURIComponent(domain);
    },
    parse: function(data) {
      if (!data || data.success !== true) return null;
      const raw = String(data.raw || '');
      let m = raw.match(/Registration Time:\s*(\d{4}-\d{2}-\d{2})/i) ||
        raw.match(/Creation Date:\s*(\d{4}-\d{2}-\d{2})/i);
      return m ? daysSinceIso(m[1]) : null;
    }
  }
];

// 查询域名注册天数（域名年龄）。返回 { creationDays, source? }：
//   ≥0 = 注册天数；-1 = 查询失败（调用方按"无信息"处理，不加风险分）。
//   source 为命中源标识（rdap / whodat / whoisjs），供证据文案标注查询依据。
// 通道顺序：RDAP（IANA 引导 → 硬编码表 → rdap.org）→ WhoDat → whoisjs；
// 仅缓存成功结论（24h）；全部失败按"无信息"处理且不写长缓存（下次再试）
async function queryDomainAge(domain) {
  const key = String(domain || '').toLowerCase();
  if (!key) return { creationDays: -1 };
  const cached = _rdapResultCache.get(key);
  if (cached && Date.now() - cached.ts < V213_DAY_MS) return cached;
  const tld = key.split('.').pop();

  // 通道 A/B/C：RDAP 主链（.cn 系无公开 RDAP，直接落 WHOIS 兜底链）
  if (!NO_RDAP_TLDS.has(tld)) {
    try {
      const base = await resolveRdapBase(tld);
      if (base) {
        const controller = new AbortController();
        const timer = setTimeout(function() { controller.abort(); }, 8000);
        const resp = await fetch(base + 'domain/' + encodeURIComponent(key), {
          signal: controller.signal,
          headers: { 'Accept': 'application/rdap+json, application/json' }
        });
        clearTimeout(timer);
        if (resp.ok) {
          try {
            const days = parseRdapCreationDays(await resp.json());
            if (days >= 0) {
              const result = { creationDays: days, source: 'rdap', ts: Date.now() };
              _rdapResultCache.set(key, result);
              return result;
            }
          } catch(e) { /* JSON 解析异常 → 落兜底链 */ }
        }
      }
    } catch(e) { /* RDAP 全链失败 → 落兜底链 */ }
  }

  // 通道 D/E：WHOIS 兜底链（覆盖 .cn/.com.cn 与 RDAP 故障场景）
  for (let i = 0; i < DOMAIN_AGE_WHOIS_PROVIDERS.length; i++) {
    const provider = DOMAIN_AGE_WHOIS_PROVIDERS[i];
    try {
      const controller = new AbortController();
      const timer = setTimeout(function() { controller.abort(); }, 8000);
      const resp = await fetch(provider.buildUrl(key), { signal: controller.signal });
      clearTimeout(timer);
      if (!resp.ok) continue;
      let data;
      try { data = await resp.json(); } catch(e) { continue; }
      const days = provider.parse(data);
      if (days !== null && days >= 0) {
        const result = { creationDays: days, source: provider.name, ts: Date.now() };
        _rdapResultCache.set(key, result);
        return result;
      }
    } catch(e) { continue; }
  }

  // 全部源失败：短时缓存 5 分钟防抖，返回"无信息"
  _rdapResultCache.set(key, { creationDays: -1, ts: Date.now() - V213_DAY_MS + 5 * 60 * 1000 });
  return { creationDays: -1 };
}

// --- ICP 备案查询 API（多源备援，参考 VirusDetector icp-api.js）---
// 调用前提：页面已扫描到格式合规的备案号（content.js icpClaimed=true）才发起
// 查询——无页面声明时不查，避免无意义请求与 popup 误报"API 不可用"。
// 关键陷阱（issue #92/#93）：uapis 对无备案/外国站仍返回 code:200，
// serviceLicence 为"查询失败"——必须校验 licence 含"ICP备/ICP证"才认定真实备案
const _icpResultCache = new Map(); // domain -> { queried, hasIcp, icpNumber, ts, service? }

const ICP_API_PROVIDERS = [
  {
    name: 'uapis',
    // v2.1.4：HTTP 404 也进入解析——实测无备案域名返回
    // 404 + {"code":"NOT_FOUND","message":"No ICP record found."}，
    // 属明确的"无备案"结论而非服务故障（须同时校验 JSON 结构防误判）
    okStatuses: [404],
    buildUrl: function(domain) {
      return 'https://uapis.cn/api/v1/network/icp?domain=' + encodeURIComponent(domain);
    },
    parse: function(data) {
      if (!data || typeof data !== 'object') return null;
      // v2.1.4：明确无备案信号（404 分支）——仅当 code 与 message
      // 双重吻合才认定，接口下线/路径变更时的 HTML 错误页走 JSON 解析失败
      if (data.code === 'NOT_FOUND') {
        return /no icp record/i.test(String(data.message || ''))
          ? { queried: true, hasIcp: false, icpNumber: '' }
          : null;
      }
      if (!(data.code === 200 || data.code === '200')) return null;
      const lic = typeof data.serviceLicence === 'string' ? data.serviceLicence.trim() : '';
      const isReal = /ICP[备证]/.test(lic);
      return { queried: true, hasIcp: isReal, icpNumber: isReal ? lic : '' };
    }
  },
  {
    // v2.1.4 重要修正：apihz 公共 ID（88888888）全网共享，限频响应与
    // 业务失败同为 code 400——旧解析把 400 一律当作"明确无备案"，
    // 限频窗口内会给声明了备案的正规站误加"伪造备案"20 分。
    // 现改为仅采信正面证据：code 200 且备案号含"ICP备/ICP证"才出结论，
    // 其余一律返回 null（无结论，继续下一源），宁缺勿错
    name: 'apihz',
    buildUrl: function(domain) {
      return 'https://cn.apihz.cn/api/wangzhan/icp.php?id=88888888&key=88888888&domain=' +
        encodeURIComponent(domain);
    },
    parse: function(data) {
      if (!data || typeof data !== 'object') return null;
      if (!(data.code === 200 || data.code === '200')) return null;
      const lic = typeof data.icp === 'string' ? data.icp.trim() : '';
      const isReal = /ICP[备证]/.test(lic);
      return isReal ? { queried: true, hasIcp: true, icpNumber: lic } : null;
    }
  }
];

async function queryIcpRecord(domain) {
  const key = String(domain || '').toLowerCase();
  if (!key) return { queried: false, hasIcp: false };
  const cached = _icpResultCache.get(key);
  if (cached && Date.now() - cached.ts < V213_DAY_MS) return cached;

  for (let i = 0; i < ICP_API_PROVIDERS.length; i++) {
    const provider = ICP_API_PROVIDERS[i];
    try {
      const controller = new AbortController();
      const timer = setTimeout(function() { controller.abort(); }, 8000);
      const resp = await fetch(provider.buildUrl(key), { signal: controller.signal });
      clearTimeout(timer);
      // v2.1.4：okStatuses 允许个别源的非 2xx 状态进入解析
      //（如 uapis 的 404=明确无备案），其余非 2xx 一律跳过该源
      const accepted = resp.ok ||
        (Array.isArray(provider.okStatuses) && provider.okStatuses.indexOf(resp.status) !== -1);
      if (!accepted) continue;
      let data;
      try { data = await resp.json(); } catch(e) { continue; }
      const parsed = provider.parse(data);
      if (!parsed || !parsed.queried) continue;
      const result = {
        queried: true,
        hasIcp: !!parsed.hasIcp,
        icpNumber: parsed.icpNumber || '',
        service: provider.name,
        ts: Date.now()
      };
      _icpResultCache.set(key, result);
      return result;
    } catch(e) {
      continue;
    }
  }

  // 所有源失败：短时缓存 5 分钟；queried:false 表示无结论（不加伪造备案分）
  const failed = { queried: false, hasIcp: false, ts: Date.now() - V213_DAY_MS + 5 * 60 * 1000 };
  _icpResultCache.set(key, failed);
  return failed;
}

// 页面未声明合规备案号时返回的占位结果（不发起网络请求）
function skipIcpQueryResult() {
  return { queried: false, hasIcp: false, skipped: true };
}

// 备案号一致性比对：工信部格式为「主体备案号」+ 可选「-N 网站序号」——
// 沪ICP备18008322号（主体号）与 沪ICP备18008322号-1（该主体的第 1 个网站）
// 是同一主体；页面页脚常声明主体号，API 返回带序号的网站号。
// v2.3.8 修复：必须先剥掉尾部的 -N 序号再比数字段，否则序号会被
// \D 过滤拼进数字串导致正规站被误判"盗用备案"（luogu.com.cn 实测误报）。
// 任一缺失则无法判定一致性
function icpNumbersMatch(claimed, apiNumber) {
  const baseDigits = function(s) {
    return String(s || '').replace(/-\d+\s*$/, '').replace(/\D+/g, '');
  };
  return !!claimed && !!apiNumber && baseDigits(claimed) !== '' &&
    baseDigits(claimed) === baseDigits(apiNumber);
}

global.__YH_DOMAIN_INTEL__ = global.__YH_DOMAIN_INTEL__ || Object.freeze({
  queryDomainAge: queryDomainAge,
  queryIcpRecord: queryIcpRecord,
  skipIcpQueryResult: skipIcpQueryResult,
  icpNumbersMatch: icpNumbersMatch
});
})(globalThis);
