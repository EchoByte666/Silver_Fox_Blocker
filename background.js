// 银狐拦截系统 v2.0.0（融合版）- 后台服务脚本
// 作者: Deep_Format (https://space.bilibili.com/1222118214)
//
// 拦截架构说明（四层防护，缺一不可）：
//   1. DNR 重定向：main_frame 导航层直接重定向到警告页（SmartScreen/webRequest 之前生效）
//   2. webNavigation.onBeforeNavigate：导航事件兜底拦截，tabs.update 同步重定向
//   3. 内容脚本 + 主世界注入：拦截页面内部的 fetch/XHR 恶意请求
//   4. 页面评分引擎（v2.0.0 新增）：内容脚本对页面做 30 项风险指标评分，
//      黑名单命中或总分达到 100 时拦截，警告页展示评分明细与正版官网引导
//
// v2.0.0 融合更新内容：
//   - 品牌冒充检测：brands.json 内置品牌库 + 远程品牌库，识别"软件品牌与
//     官网域名不匹配"的仿冒站，警告页提供"前往正版网站"引导
//   - 内置默认白名单（qq.com / microsoft.com / apple.com / lestore.lenovo.com），
//     始终豁免拦截且不占用用户白名单存储
//   - 拦截记录持久化（blockedPage_<tabId>），SW 重启后警告页仍可恢复评分明细
//   - 徽标已移除（v2.1.0）：工具栏图标不再显示拦截次数/'!' 提示（v1.1.1 曾提示 '!'）
//   - 连字符可疑域名模式扩展支持 *.cc（v1.1.1 仅 *.com.cn / *.hl.cn）

// ===== v2.7.0 模块化 =====
// 共享配置与纯函数已抽取至 modules/（单一事实来源，消灭"两处同步"副本）：
//   modules/core.js          配置常量 + 域名/品牌纯函数 + 五张平台豁免表
//   modules/sandbox-probe.js AI 外链沙箱防追踪探测（缓存/去重/8s 超时）
// 经典 Service Worker 以 importScripts 加载（顺序保证：core 先于 sandbox-probe），
// 模块以 globalThis 命名空间暴露，此处解构为顶层绑定——全部调用点零改动
importScripts('modules/core.js', 'modules/sandbox-probe.js');

const CORE = globalThis.__YH_CORE__;
const {
  DEBUG, LOG, debug,
  HARDCODED_DOMAINS, RULE_SOURCE_URLS, CLOUD_WHITELIST_URL, BRAND_SOURCE_URL,
  DEFAULT_WHITELIST, FETCH_TIMEOUT_MS, OFFSCREEN_WAIT_MS,
  matchesPatternDomain, matchesDomainList, matchesBlockedDomain,
  getRegistrableDomain,
  isGovCnHostname: isGovCn,
  levenshteinWithin1, isShortLatinKeyword, shortKeywordBoundaryHit,
  brandDomainKeywordHit,
  DEVELOPER_PLATFORM_DOMAINS, SEARCH_ENGINE_DOMAINS,
  isAiChatHostname, isUgcHostname, isSecurityForumHostname
} = CORE;
const { sandboxProbeUrl } = globalThis.__YH_SANDBOX__;

// ===== 运行时缓存 =====
// SW 每次唤醒后通过 loadCache() 从 storage 恢复
const cache = {
  blocklist: [], whitelist: [], cloudWhitelist: [], bypass: {},
  unfrozen: {},    // v2.1.3 r3 新增：解冻窗口期（hostname → 解冻时间戳）
  blockedCount: 0, enabled: true, status: 'pending',
  brandConfig: [], // v2.0.0 新增：品牌库配置（评分引擎的品牌冒充检测用）
  brandsVer: ''    // v2.1.3 新增：品牌库生成时的扩展版本（升级后强制重算）
};

// 域名匹配 Set 缓存：规则变化时重建，导航匹配查询 O(1)。
// 旧实现对几千个域名逐条 trim/replace，导航频繁时字符串开销大
let blocklistSet = new Set();
let cloudWhitelistSet = new Set();
let localWhitelistSet = new Set();       // 本地用户白名单（handleNav 高频路径用）
let defaultWhitelistSet = new Set();     // v2.0.0 新增：内置默认白名单匹配集
// v2.1.1 新增：全部放行域名的合并匹配集（云+默认+本地白名单）。
// onCommitted 每次导航都要做放行判断，原先每次现场调
// getAllowedDomains() 合并三个数组再线性扫描，改为 rebuildDomainSets
// 时构建一次 Set，导航路径直接 setMatches（O(域名标签数)）
let allAllowedSet = new Set();

// 防止同一标签页重复重定向到警告页
const redirectingTabs = {};

// 被拦截页面的信息缓存（warning 页查询用，避免 URL 参数中带恶意域名）。
// v2.0.0：附带评分明细 score，供警告页展示"风险评分"面板。
// 使用 Map 并带时间戳，keepAlive 定时修剪过期条目，防止长期运行内存膨胀
const blockedPageUrls = new Map();

// DNR 重定向不会自动携带原始 URL，因此按标签页保存最近一次外部导航。
// 使用 Map（保持插入序），超量时修剪最旧条目
const lastNavigationUrls = new Map();

// ===== 域名匹配工具 =====
// v2.7.0：matchesPatternDomain / matchesDomainList / matchesBlockedDomain /
// isGovCn（core.isGovCnHostname）/ getRegistrableDomain / levenshteinWithin1 /
// isShortLatinKeyword / shortKeywordBoundaryHit / brandDomainKeywordHit
// 已全部抽取至 modules/core.js（文件顶部解构引入）

// 高频路径：用预构建的 Set 判断 hostname 或其任意父域是否在集合中
// 等价于 hostname === domain || hostname.endsWith('.' + domain)
function setMatches(set, hostname) {
  if (!set || set.size === 0 || !hostname) return false;
  const labels = hostname.split('.');
  for (let i = 0; i < labels.length; i++) {
    if (set.has(labels.slice(i).join('.'))) return true;
  }
  return false;
}

// 把域名列表规范化后构建为 Set（去除 * 前缀与首尾点、统一小写）
function buildDomainSet(domains) {
  const set = new Set();
  for (const entry of (domains || [])) {
    const domain = String(entry || '').toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
    if (domain) set.add(domain);
  }
  return set;
}

// cache 数据变化后调用，重建全部匹配 Set
function rebuildDomainSets() {
  blocklistSet = buildDomainSet(cache.blocklist);
  cloudWhitelistSet = buildDomainSet(cache.cloudWhitelist);
  localWhitelistSet = buildDomainSet(normalizeWhitelist(cache.whitelist));
  // 默认白名单是代码常量，重复构建幂等，统一在此处维护
  defaultWhitelistSet = buildDomainSet(normalizeWhitelist(DEFAULT_WHITELIST));
  // v2.1.1：合并放行集（onCommitted 高频路径用，替代每次现场合并数组）
  allAllowedSet = buildDomainSet(getAllowedDomains());
}

// v2.7.0：matchesBlockedDomain 已抽取至 modules/core.js（顶部解构引入）

// ===== 白名单工具 =====

function normalizeWhitelistDomain(entry) {
  let value = String(entry || '').trim().toLowerCase();
  if (!value) return '';
  try {
    if (/^https?:\/\//.test(value)) {
      const parsed = new URL(value);
      value = parsed.hostname.toLowerCase();
    } else if (value.includes('://')) {
      return '';
    }
  } catch(e) { return ''; }
  value = value.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  return value && value.includes('.') && !/[\s\/?#:@\[\]]/.test(value) ? value : '';
}

function normalizeWhitelist(entries) {
  const domains = [];
  for (let i = 0; i < (entries || []).length; i++) {
    const domain = normalizeWhitelistDomain(entries[i]);
    if (domain && domains.indexOf(domain) === -1) domains.push(domain);
  }
  return domains;
}

// 全部放行域名合并（v2.0.0 起含内置默认白名单）：
// 云白名单 + 内置默认白名单 + 用户本地白名单，用于 DNR allow 规则与注入器
function getAllowedDomains() {
  const domains = (cache.cloudWhitelist || []).slice();
  const defaultDomains = normalizeWhitelist(DEFAULT_WHITELIST);
  const localDomains = normalizeWhitelist(cache.whitelist);
  for (let i = 0; i < defaultDomains.length; i++) {
    if (domains.indexOf(defaultDomains[i]) === -1) domains.push(defaultDomains[i]);
  }
  for (let i = 0; i < localDomains.length; i++) {
    if (domains.indexOf(localDomains[i]) === -1) domains.push(localDomains[i]);
  }
  return domains;
}

// v2.0.0 新增：判断 hostname 是否命中内置默认白名单（高频路径用预构建 Set）
function isDefaultWhitelisted(hostname) {
  return setMatches(defaultWhitelistSet, hostname);
}

// v2.7.0：isGovCn 已抽取至 modules/core.js（isGovCnHostname，顶部解构时
// 重命名回 isGovCn；统一含 gov.hk / 政务.cn 扩展后缀）

function matchesLocalWhitelist(url) {
  // 高频路径：直接查预构建的 Set（rebuildDomainSets 时随 whitelist 一起更新）
  let hostname;
  try { hostname = new URL(url).hostname.toLowerCase(); } catch(e) { return false; }
  return setMatches(localWhitelistSet, hostname);
}

// v2.7.0：levenshteinWithin1 / isShortLatinKeyword / shortKeywordBoundaryHit /
// brandDomainKeywordHit 已抽取至 modules/core.js（顶部解构引入）

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

// ===== v2.2.0 异步增强计分常量（与 popup.js renderIntel 规则保持一致，
// 修改时两处同步）=====
const AGE_NEW_DAYS = 30;
const AGE_RECENT_DAYS = 90;
const AGE_MATURE_DAYS = 730;   // ≥730 天视为老域名 → -15 抵扣
const AGE_MATURE_BONUS = -15;
const ICP_MATCH_BONUS = -80;   // 备案号核验一致 → 大幅减分
const ICP_STOLEN_PENALTY = 30; // 域名已备案但页面号码对不上 → 盗用他人备案号

// v2.6.0：连字符模式域名（*.com.cn/*.hl.cn/*.cc）的异步 ICP 校平系数——
// 形态弱信号静态层固定 +15，异步反查后按实际备案状态双向修正（见 enhanceScoreAsync）
const PATTERN_DOMAIN_ICP_BONUS = -20;   // 域名实际持有有效备案 → 抵扣
const PATTERN_DOMAIN_NOICP_PENALTY = 8; // API 明确查无备案 → 疑点印证温和加权

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

// --- 异步增强与升级拦截 ---
// scorePage 同步回执发出后调用（不阻塞响应）。查域名年龄；
// 仅当页面已声明合规备案号（icpClaimed）时才查 ICP API 核验备案。
// v2.2.0：负分抵扣（备案核验一致 -80 / 老域名 -15）把总分拉回阈值以下时
// 通知 content 回撤横幅/冻结；命中新增风险项且总分达硬拦截线
// → 执行拦截（复用 blockedInfo 机制，警告页可展示含增强明细的完整评分）
// v2.2.2：扩展为升降级双向对账（scoreAdjusted 消息）——增强前后 UI 层级
// 不一致即通知 content 调整，无论方向均伴随 Toast；增强结论缓存于
// _enhancedVerdicts 供同步决策消费，消除重评闪烁
const _enhanceInFlight = new Set();

// ===== v2.2.2：增强终局结论缓存与 UI 层级判定 =====

// 增强终局结论缓存（URL → 增强后总分与证据类别），作用有二：
//   1) 同步决策消费——DOM 变化触发重评时 scorePage 直接采用增强后结论，
//      避免每次都"按原始高分注入横幅 → 异步再回撤"的闪烁循环，
//      页面刷新后也立即得到最终层级而非先展示过时结论；
//   2) 对账去重——增强结论未变化时不重复发 scoreAdjusted / 弹 Toast
const _enhancedVerdicts = new Map();
const ENHANCED_VERDICT_TTL_MS = 30 * 60 * 1000;   // 30 分钟过期：过期后重新查询重算
const ENHANCED_VERDICT_MAX = 200;                 // 容量上限（Map 保持插入序，淘汰最旧）

function getEnhancedVerdict(url) {
  const v = _enhancedVerdicts.get(url);
  if (!v) return null;
  if (Date.now() - v.ts > ENHANCED_VERDICT_TTL_MS) { _enhancedVerdicts.delete(url); return null; }
  return v;
}

// UI 层级判定（与 scorePage 同步决策严格对齐，修改时两处同步）：
//   warn   ≥100（是否冻结由 structure/resource 类证据另行决定）
//   notice 80~99
//   card   60~79 或存在品牌冒充嫌疑（!!result.brand 即嫌疑）
//   clear  其余
function uiLevelOf(total, brandSuspicion) {
  if (total >= 100) return 'warn';
  if (total >= 80) return 'notice';
  if (total >= 60 || brandSuspicion) return 'card';
  return 'clear';
}

// 品牌冒充嫌疑标记（与 scorePage 同步路径 hasBrandSuspicion 同义，两处同步）
function hasBrandSuspicionFlag(result) {
  return (Array.isArray(result.details) && result.details.some(
    function(item) { return item.matched && item.points > 0 && item.id === 'domainBrandImpersonation'; })) ||
    !!result.brand;
}

async function enhanceScoreAsync(tabId, url, result) {
  const key = tabId + ':' + url;
  if (_enhanceInFlight.has(key)) return;
  _enhanceInFlight.add(key);
  // v2.6.0：先确保用户信任表就绪（isUserTrustedActive 为同步读）
  await ensureUserTrustLoaded();
  try {
    let hostname = '';
    try { hostname = new URL(url).hostname.toLowerCase(); } catch(e) { return; }
    const domain = getRegistrableDomain(hostname);
    if (!domain) return;
    // 域龄始终查；ICP 仅当页面已声明合规备案号时才查（content.js icpClaimed）。
    // v2.3.0：可信 AI 对话页强制跳过 ICP 核验——对话内容里的备案号是
    // AIGC/UGC 文本而非页脚声明，"盗用备案"+30/"查无备案"+20 惩罚不生效。
    // v2.4.0：UGC 平台（ugcPage）同列豁免——帖子里粘贴的备案号同样是内容
    const ageInfo = await queryDomainAge(domain);
    const icpInfo = (result.icpClaimed &&
        !(result.aiChatPage || result.ugcPage || result.secForum))
      ? await queryIcpRecord(domain)
      : skipIcpQueryResult();

    // 基于原结果构造增强视图（不改原对象，明细副本进拦截记录）
    const details = Array.isArray(result.details) ? result.details.slice() : [];
    const catSet = new Set(Array.isArray(result.categoriesList) ? result.categoriesList : []);
    let enhancedTotal = Number(result.total) || 0;

    // 增强 1：新注册域名（domain 类证据）。
    // v2.1.4：证据文案按实际命中的数据源标注查询依据（RDAP/WHOIS），
    // 与"拦截文案准确反映检测依据"的项目原则一致
    const days = ageInfo.creationDays;
    const ageSourceLabel = ageInfo.source === 'rdap' ? 'RDAP 查询' : 'WHOIS 查询';
    if (days >= 0 && days < 30) {
      enhancedTotal += 40;
      catSet.add('domain');
      details.push({ id: 'domainYoung', label: '新注册域名', points: 40, matched: true,
        evidence: '注册仅 ' + days + ' 天（' + ageSourceLabel + '）' });
    } else if (days >= 30 && days < 90) {
      enhancedTotal += 20;
      catSet.add('domain');
      details.push({ id: 'domainYoung', label: '近期注册域名', points: 20, matched: true,
        evidence: '注册 ' + days + ' 天（' + ageSourceLabel + '）' });
    }

    // v2.2.0 增强：老域名抵扣（domain 类负分）——银狐站用完即弃，
    // 活过两年的域名是弱安全信号；数据现成，零额外请求
    if (days >= AGE_MATURE_DAYS) {
      enhancedTotal += AGE_MATURE_BONUS;
      details.push({ id: 'domainMature', label: '老域名安全信号', points: AGE_MATURE_BONUS,
        matched: true, evidence: '注册 ' + days + ' 天（' + ageSourceLabel + '）' });
    }

    // v2.6.0 增强：连字符模式域名的备案反查校平。*.com.cn/*.hl.cn/*.cc
    // 连字符形态正规企业同样在用（跨国品牌中英拼接名等），同步静态分固定
    // +15 属"宁枉勿纵"。此处异步反查按事实修正：
    //   实际持有有效 ICP 备案 → PATTERN_DOMAIN_ICP_BONUS -20（主体真实运营）；
    //   API 明确查无备案     → +8（形态疑点获得独立印证，温和加权）；
    //   API 全部不可用       → 不动分值（失败安全，与三态核验同一哲学）。
    // 仅在页面未声明备案号时执行——声明场景走下方三态核验（一致-80/盗用+30），
    // 避免同域两套口径叠加；可信内容平台整体跳过
    if (result.patternDomainHit && !result.icpClaimed &&
        !(result.aiChatPage || result.ugcPage || result.secForum)) {
      const patIcpInfo = await queryIcpRecord(domain);
      if (patIcpInfo && patIcpInfo.queried) {
        if (patIcpInfo.hasIcp) {
          enhancedTotal += PATTERN_DOMAIN_ICP_BONUS;
          details.push({ id: 'patternDomainIcpOk', label: '连字符域名持有有效备案',
            points: PATTERN_DOMAIN_ICP_BONUS, matched: true,
            evidence: domain + ' 已在工信部备案' +
              (patIcpInfo.icpNumber ? '（' + patIcpInfo.icpNumber + '）' : '') +
              '，主体真实存在（API 核验），形态疑点校平' });
        } else {
          enhancedTotal += PATTERN_DOMAIN_NOICP_PENALTY;
          catSet.add('domain');
          details.push({ id: 'patternDomainNoIcp', label: '连字符域名查无备案',
            points: PATTERN_DOMAIN_NOICP_PENALTY, matched: true,
            evidence: domain + ' 无任何 ICP 备案记录（API 核验），形态疑点加重' });
        }
      }
    }

    // v2.2.0 增强：ICP 备案三态核验（structure 类证据）。
    //   一致（域名已备案 且 页面声明号码与 API 记录数字段相同）→ -80：
    //     强信任证据——盗用他人备案号很难连号码一起伪造一致；
    //   域名已备案但号码对不上 → +30：比"查无备案"更隐蔽的仿冒手法，
    //     旧逻辑完全抓不到（查实了只显示不计分）；
    //   域名无备案 → 维持原 +20（页面声明了备案但域名查无记录）。
    // 外国站不声明备案，天然规避"API 对外国站返回查询失败"的误判陷阱
    // v2.2.3：icpVerifiedConsistent 标记供两处使用——
    //   1) 对账层的品牌嫌疑判定（见下方 brandSuspicion）；
    //   2) 写入终局结论缓存供同步决策消费（刷新后同样解除卡片钉定）
    let icpVerifiedConsistent = false;
    if (result.icpClaimed && icpInfo.queried && icpInfo.hasIcp) {
      const claimed = String(result.icpNumber || '');
      const numbersConsistent = icpNumbersMatch(claimed, icpInfo.icpNumber);
      if (numbersConsistent) {
        icpVerifiedConsistent = true;
        enhancedTotal += ICP_MATCH_BONUS;
        details.push({ id: 'icpVerified', label: '备案号核验一致', points: ICP_MATCH_BONUS,
          matched: true, evidence: claimed + ' 与 ' + domain +
          ' 备案记录相符（API 核验）' });
      } else {
        enhancedTotal += ICP_STOLEN_PENALTY;
        catSet.add('structure');
        details.push({ id: 'icpStolen', label: '涉嫌盗用他人备案号', points: ICP_STOLEN_PENALTY,
          matched: true, evidence: '页面声明 ' + (claimed || '备案') + '，但 ' + domain +
            ' 的备案记录为 ' + (icpInfo.icpNumber || '其他主体') + '（API 核验）' });
      }
    } else if (result.icpClaimed && icpInfo.queried && !icpInfo.hasIcp) {
      enhancedTotal += 20;
      catSet.add('structure');
      details.push({ id: 'icpFake', label: '备案号与域名不符', points: 20, matched: true,
        evidence: '页面声明备案但 ' + domain + ' 无备案记录（API 核验）' });
    }

    // 升级判定：与同步路径同一标准（150 分 + 2 类证据）。
    // v2.2.0：提前计算，避免同一页面既收到降级回撤又被跳警告页的矛盾决策
    const willUpgrade = enhancedTotal >= 150 && catSet.size >= 2;

    // v2.2.2：登记增强终局结论。verdictUnchanged 表示本轮结论与上轮一致——
    // 同步决策已消费过该结论（getEnhancedVerdict），content 当前展示即最终
    // 层级，无需再发对账消息重复打扰
    const verdictUnchanged = (function() {
      const prior = getEnhancedVerdict(url);
      return !!prior && prior.total === enhancedTotal;
    })();
    _enhancedVerdicts.set(url, {
      total: enhancedTotal,
      categories: catSet.size,
      categoriesList: Array.from(catSet),
      icpVerified: icpVerifiedConsistent,
      ts: Date.now()
    });
    if (_enhancedVerdicts.size > ENHANCED_VERDICT_MAX) {
      _enhancedVerdicts.delete(_enhancedVerdicts.keys().next().value);
    }

    // v2.2.2 升降级对账：同步决策先于增强数据返回，页面可能已按原始分数
    // 注入横幅/卡片甚至冻结。增强后的 UI 层级与同步层级不一致且不会升级
    // 硬拦截时，发 scoreAdjusted 让 content 把 UI 调整到目标层级——无论
    // 升级还是回撤均伴随顶部 Toast。
    // v2.2.1 缺陷修复：旧回撤仅在原始总分 ≥100 时触发，60~99 分的琥珀
    // 卡片场景被遗漏（如评分 70 弹卡后备案核验一致 -80 → 卡片残留不消失）
    if (!willUpgrade && !verdictUnchanged) {
      const originalTotal = Number(result.total) || 0;
      // v2.2.3：备案核验一致是强信任证据（盗用备案号很难连号码一起伪造
      // 一致）——解除品牌嫌疑对 UI 层级的钉定，让 -80 抵扣真正生效。
      // 否则嫌疑页分数降到 -10 仍被钉在 card 层：卡片永不撤除、对账判定
      // "层级没变"连 Toast 都不发（v2.2.2 上线后用户实测复现的残留问题）
      const brandSuspicion = hasBrandSuspicionFlag(result) && !icpVerifiedConsistent;
      const syncLevel = uiLevelOf(originalTotal, brandSuspicion);
      const enhancedLevel = uiLevelOf(enhancedTotal, brandSuspicion);
      if (enhancedLevel !== syncLevel) {
        const enhancedCatList = Array.from(catSet);
        const hardEvidence = enhancedCatList.indexOf('structure') !== -1 ||
          enhancedCatList.indexOf('resource') !== -1;
        try {
          chrome.tabs.sendMessage(tabId, {
            action: 'scoreAdjusted',
            fromLevel: syncLevel, level: enhancedLevel,
            total: enhancedTotal, previousTotal: originalTotal,
            details: details.filter(function(item) { return item.matched; }),
            categoriesList: enhancedCatList,
            // 目标为警示层时附带冻结指令（门槛与同步路径一致：
            // structure/resource 类证据 + 不在解冻窗口期/用户信任期内——
            // v2.6.0 信任记忆与同步路径同门槛，两处同步）
            freeze: enhancedLevel === 'warn' && hardEvidence &&
              !isRecentlyUnfrozen(url) && !isUserTrustedActive(hostname),
            // 卡片跟随规则与同步路径一致：card 层必有；notice/warn 层仅
            // 纯高分达硬拦截线时叠加（legacyHit/strongSignal 在本路径恒 false）
            card: enhancedLevel === 'card' ||
              ((enhancedLevel === 'notice' || enhancedLevel === 'warn') && enhancedTotal >= 150)
          }, function() { void chrome.runtime.lastError; });
        } catch(e) { /* 页面可能已导航离开 */ }
        debug('enhanceScoreAsync 升降级对账 tabId=' + tabId +
          ' ' + syncLevel + '→' + enhancedLevel +
          ' original=' + originalTotal + ' enhanced=' + enhancedTotal);
      }
    }

    // 升级拦截（回撤判定已确认不会与本决策冲突）
    if (!willUpgrade) return;

    // 拦截前重新校验豁免状态（查询期间用户可能已加白/关开关/换页）
    await refreshWhitelistCache();
    const stillAllowed = !cache.enabled ||
      setMatches(cloudWhitelistSet, hostname) ||
      isDefaultWhitelisted(hostname) ||
      isGovCn(hostname) ||
      matchesLocalWhitelist(url) ||
      isRecentlyBypassed(url);
    if (stillAllowed) return;
    // 标签页仍在目标页才拦截（用户可能已导航离开）
    try {
      const tab = await chrome.tabs.get(tabId);
      if (!tab || !tab.url) return;
      const tabHost = (function() {
        try { return new URL(tab.url).hostname.toLowerCase(); } catch(e) { return ''; }
      })();
      if (tabHost !== hostname) return;
    } catch(e) { return; } // 标签页已关闭

    // 防抖：与同步拦截共用 redirectingTabs
    const reportKey = tabId + ':' + url;
    if (redirectingTabs[reportKey] && Date.now() - redirectingTabs[reportKey] < 5000) return;
    redirectingTabs[reportKey] = Date.now();

    const enhancedResult = Object.assign({}, result, {
      total: enhancedTotal,
      details: details,
      categories: catSet.size,
      categoriesList: Array.from(catSet)
    });
    cache.blockedCount++;
    storageSet({ blockedCount: cache.blockedCount });
    updateBadge();
    saveBlockedPageInfo(tabId, {
      url: url, fromUrl: url, reason: 'score', score: enhancedResult, ts: Date.now()
    });
    const warningUrl = chrome.runtime.getURL('warning.html') + '?tab=' + tabId +
      '&score=1&url=' + encodeURIComponent(url) + '&t=' + Date.now();
    // v2.2.4：跳转前先通知原页面弹"已达到拦截标准"升级 Toast（此前升级
    // 硬拦截完全静默——页面毫无征兆直接变成警告页），短暂停留让提示
    // 可见后再执行跳转
    try {
      chrome.tabs.sendMessage(tabId, {
        action: 'scoreEscalated',
        total: enhancedTotal,
        details: details.filter(function(item) { return item.matched; })
      }, function() { void chrome.runtime.lastError; });
    } catch(e) { /* 页面可能已导航离开 */ }
    setTimeout(function() {
      try {
        chrome.tabs.update(tabId, { url: warningUrl }, function() {
          void chrome.runtime.lastError;
        });
      } catch(e) { /* 标签页可能已关闭 */ }
    }, 1600);
    debug('异步增强拦截! tabId=' + tabId + ' total=' + enhancedTotal +
      ' age=' + days + 'd icpFake=' + (result.icpClaimed && icpInfo.queried && !icpInfo.hasIcp) +
      ' url=' + url);
  } finally {
    _enhanceInFlight.delete(key);
  }
}

// ===== 品牌库与品牌核查（v2.0.0 新增）=====

// 对内容脚本的评分结果做后台二次品牌核查：
// 内容脚本的品牌配置可能未就绪（SW 刚唤醒/网络失败），此处统一补检，
// 命中"品牌冒充"加 30 分；叠加可疑域名模式再加 20 分。
// 若 content 已检出（details 里 matched=true），不会重复加分
function applyBrandCheck(result, url) {
  let hostname;
  try { hostname = new URL(url).hostname.toLowerCase(); } catch(e) { return result; }
  // v2.1.5：开发者平台与搜索引擎豁免（与 content.js 同名表两处同步）——
  // 平台页面对品牌的提及是文档/讨论语境，搜索结果页标题必然包含用户
  // 查询的品牌词，均为"提及"而非"冒充"，整体跳过补检。
  // v2.3.0：可信 AI 对话页同列豁免——对话正文/标题高频出现任意品牌词
  //（用户提问即决定），是问答语境而非冒充。
  // v2.4.0：UGC 平台同列豁免——帖子/评论/视频标题对品牌的提及
  // 是内容语境（测评、吐槽、讨论）而非冒充，整体跳过补检
  if (DEVELOPER_PLATFORM_DOMAINS.some(function(platformDomain) {
    return hostname === platformDomain || hostname.endsWith('.' + platformDomain);
  }) || SEARCH_ENGINE_DOMAINS.some(function(searchDomain) {
    return hostname === searchDomain || hostname.endsWith('.' + searchDomain);
  }) || isAiChatHostname(hostname) || isUgcHostname(hostname) ||
    isSecurityForumHostname(hostname)) return result;
  const title = String(result.title || '').toLowerCase().replace(/\s+/g, '');
  const brandHint = String(result.brand || '').toLowerCase().replace(/\s+/g, '');
  let matchedBrand = null;
  // v2.1.1 两阶段修复（外部审查指出单遍 .some 的判定缺陷）：
  // 旧逻辑遇到第一个"关键词命中且非官方域"的品牌即停止——若 hostname
  // 实际命中后面某品牌的官方/可信域（如 360 官方页提及"腾讯电脑管家"），
  // 后续品牌的官方域检查被短路，正版站会被误判冒充第一个品牌。
  // 新逻辑分两遍：
  //   第一遍：只要 hostname 命中任何品牌的官方/可信域 → 整体放行
  //   第二遍：取第一个"关键词命中且不在官方/可信域"的品牌作为冒充判定
  const hostMatchesDomain = function(domain) {
    domain = String(domain).toLowerCase();
    return hostname === domain || hostname.endsWith('.' + domain);
  };
  // 第一遍：官方域/可信域全量扫描
  const onOfficialSite = cache.brandConfig.some(function(rule) {
    return (rule.officialDomains || []).some(hostMatchesDomain) ||
      (rule.trustedDomains || []).some(hostMatchesDomain);
  });
  // 第二遍：非官方站点上找第一个关键词命中的品牌
  // v2.3.9：短拉丁词（<5 字符，如远程库 LINE 的 "line"）子串碰撞率过高——
  // 标题含 online/offline/deadline/cline 的页面都被旧逻辑判为 LINE 冒充。
  // 短词在未去空格原文上做词边界复核，长短词行为不变
  if (!onOfficialSite) {
    cache.brandConfig.some(function(rule) {
      const matched = (rule.keywords || []).some(function(keyword) {
        const normalizedKeyword = String(keyword).toLowerCase().replace(/\s+/g, '');
        if (!title.includes(normalizedKeyword) && !brandHint.includes(normalizedKeyword)) return false;
        if (isShortLatinKeyword(normalizedKeyword)) {
          return shortKeywordBoundaryHit(normalizedKeyword, result.title) ||
            shortKeywordBoundaryHit(normalizedKeyword, result.brand);
        }
        return true;
      });
      if (matched) { matchedBrand = rule; return true; }
      return false;
    });
  }
  if (!matchedBrand) return result;
  const details = Array.isArray(result.details) ? result.details : [];
  // 多品牌软件目录站（如正规下载站）不做品牌冒充判定
  if (details.some(function(item) { return item.id === 'softwareCatalog' && item.matched; })) return result;
  // 品牌冒充：+30 分（已由 content 检出时不重复加分）
  let detail = details.find(function(item) { return item.id === 'brandMismatch'; });
  if (!detail) {
    detail = { id: 'brandMismatch', label: '软件品牌与官网域名不匹配', points: 0, matched: false, evidence: '' };
    details.push(detail);
  }
  if (!detail.matched) result.total = Number(result.total || 0) + 30;
  detail.points = 30;
  detail.matched = true;
  detail.evidence = matchedBrand.name;
  // v2.1.2 强信号 A（漏报修复，与 content.js 同步）+ v2.1.3 模糊匹配：
  // 域名品牌词仿冒——hostname 含品牌英文关键词（≥3 字符纯拉丁词）却不在
  // 官方域，typosquatting 证据（如 huorongaq.com 含 "huorong" 冒充火绒安全）。
  // v2.1.3：增加编辑距离 ≤1 比对，覆盖拼写变体（huorrong.com.cn 双写 r，
  // 精确子串匹配抓不到）。v2.2.0：命中改为 +30 计分参与综合裁决，不再直拦。
  // v2.3.9：短词改走强边界（brandDomainKeywordHit），注册段提取提升到循环外
  const impLabels = hostname.split('.');
  const impSecond = impLabels.length >= 2 ? impLabels[impLabels.length - 2] : '';
  const impCnDouble = impLabels[impLabels.length - 1] === 'cn' &&
    ['com','net','org','gov','edu','ac'].includes(impSecond);
  const impCut = impCnDouble ? 2 : 1;
  const impRegistrable = impLabels.length > impCut
    ? impLabels[impLabels.length - impCut - 1] : impLabels[0] || '';
  const domainImpersonated = (matchedBrand.keywords || []).some(function(keyword) {
    const kw = String(keyword).toLowerCase();
    if (kw.length < 3 || !/^[a-z0-9]+$/.test(kw)) return false;
    // 路径 1：子串包含（短词需强边界：cline.bot 不再命中 LINE）
    if (brandDomainKeywordHit(kw, hostname, impRegistrable)) return true;
    // 路径 2：编辑距离 ≤1 的拼写变体（huorrong ↔ huorong，仅 ≥6 字符长词）
    if (kw.length >= 6 && impRegistrable &&
        Math.abs(impRegistrable.length - kw.length) <= 1 &&
        levenshteinWithin1(impRegistrable, kw)) return true;
    return false;
  });
  if (domainImpersonated) {
    let domainDetail = details.find(function(item) { return item.id === 'domainBrandImpersonation'; });
    if (!domainDetail) {
      domainDetail = { id: 'domainBrandImpersonation', label: '域名仿冒品牌关键词', points: 0, matched: false, evidence: '' };
      details.push(domainDetail);
    }
    if (!domainDetail.matched) result.total = Number(result.total || 0) + 30;
    domainDetail.points = 30;
    domainDetail.matched = true;
    domainDetail.evidence = matchedBrand.name + ' + ' + hostname;
    // v2.2.0：品牌/域名仿冒不再作为强信号直拦——保留 +30 计分，
    // 参与综合裁决（分层策略 + 放行卡片承接），与 content.js 强特征
    // 收紧（仅 noahApi/adseoResource）保持同一口径
  }
  // 品牌冒充 + 可疑域名模式组合：+20 分
  const labels = hostname.split('.');
  const patternDomain = (labels.length >= 3 && labels[labels.length - 1] === 'cn' &&
    (labels[labels.length - 2] === 'com' || labels[labels.length - 2] === 'hl') &&
    labels[labels.length - 3].includes('-')) ||
    (labels.length >= 2 && labels[labels.length - 1] === 'cc' &&
    labels[labels.length - 2].includes('-'));
  if (patternDomain) {
    let combo = details.find(function(item) { return item.id === 'brandPatternCombo'; });
    if (!combo) {
      combo = { id: 'brandPatternCombo', label: '品牌冒充与可疑域名组合', points: 0, matched: false, evidence: '' };
      details.push(combo);
    }
    if (!combo.matched) result.total = Number(result.total || 0) + 20;
    combo.points = 20;
    combo.matched = true;
    combo.evidence = matchedBrand.name + ' + ' + hostname;
  }
  result.details = details;
  result.brand = matchedBrand.name;
  result.officialUrl = matchedBrand.officialUrls && matchedBrand.officialUrls[0] || '';
  return result;
}

// v2.7.0：DEVELOPER_PLATFORM_DOMAINS / SEARCH_ENGINE_DOMAINS / AI_CHAT_PLATFORM_DOMAINS /
// UGC_PLATFORM_DOMAINS / SECURITY_FORUM_DOMAINS 及 isAiChatHostname / isUgcHostname /
// isSecurityForumHostname 已抽取至 modules/core.js（顶部解构引入）

// ===== 品牌关键词本地修正表（v2.1.0 新增）=====
// 远程品牌库的关键词可能过泛，导致正规网站被误判品牌冒充。典型案例：
// 腾讯电脑管家的远程关键词是"电脑管家"——这是一个半通用词，
// 2345安全卫士官网（safe.2345.cc）的 SEO 标题
// "2345安全卫士官网下载-免费杀毒软件-电脑管家-软件管理-…"就包含它，
// 命中后因域名非 guanjia.qq.com 被判"疑似冒充腾讯电脑管家"（误报）。
// 此表按品牌名覆盖关键词列表：只影响本地匹配语义，不改动远程数据；
// 冒充站几乎必然在标题中使用完整品牌名（其目的就是蹭全名搜索流量），
// 收紧为全名匹配不会漏掉真实冒充站。新增误报在此追加即可。
//
// v2.1.5 补充：为什么内置 brands.json 洗了关键词还要在此覆盖——
// mergeBrandConfig 对同名牌的 keywords 取"内置 ∪ 远程"并集，远程源若
// 仍带旧泛词（如 Google Chrome 的 "google"/"谷歌"、Clash Verge 的
// "clash"），并集会把洗掉的词重新引入。修正表在合并之后执行、整表
// 替换 keywords，是唯一能压过远程脏数据的关口
const BRAND_KEYWORD_OVERRIDES = {
  '腾讯电脑管家': ['腾讯电脑管家', '腾讯管家'],
  // 公司级泛词不得用于产品冒充判定：任何提到 Google 的页面（含 *.google
  // 官方域之外的合法提及）都会被判"冒充 Chrome"；实测 antigravity.google
  // 曾因 hostname 含 "google" 触发域名仿冒强特征被硬拦
  'Google Chrome': ['chrome', '谷歌浏览器', '谷歌chrome'],
  // "clash" 是普通英文单词，新闻/游戏语境高频出现，单独成词误报面过大
  'Clash Verge': ['clash verge', 'clashverge']
};

// 对品牌规则数组应用本地关键词修正（返回新数组，不改动入参）
function applyBrandOverrides(brands) {
  return brands.map(function(rule) {
    const override = BRAND_KEYWORD_OVERRIDES[rule.name];
    return override ? Object.assign({}, rule, { keywords: override }) : rule;
  });
}

// v2.1.3 修复（用户实测 yibeiqishui.com.cn 漏拦指出）：品牌库合并。
// 旧逻辑"远程源优先、成功即覆盖"会让远程数据完全冲掉内置 brands.json
// ——本地新增的关键词（汽水音乐的 "qishui"）被远程旧数据
//（仅 ["汽水音乐","qishuimusic"]）覆盖丢失，域名仿冒检测随之失效。
// 新逻辑：内置文件始终参与，与远程数据按品牌名合并——
//   同名牌：keywords/officialDomains/trustedDomains/officialUrls 取并集
//          （本地配置永不丢失，远程修正照常引入）
//   远程独有品牌：直接引入（远程库比内置丰富，如微信输入法/腾讯会议等）
//   内置独有品牌：保留（远程下架 ≠ 放弃保护）
// 合并后再应用 BRAND_KEYWORD_OVERRIDES（本地收紧修正最终生效）
function dedupeStrings(arr) {
  const seen = new Set();
  const out = [];
  for (const item of (arr || [])) {
    const s = String(item);
    if (s && !seen.has(s)) { seen.add(s); out.push(s); }
  }
  return out;
}

function mergeBrandConfig(builtinBrands, remoteBrands) {
  const builtinByName = new Map();
  for (const rule of builtinBrands) builtinByName.set(rule.name, rule);
  const merged = [];
  const seenNames = new Set();
  // 远程条目为基底遍历：同名牌做字段并集，远程独有直接引入
  for (const remote of remoteBrands) {
    seenNames.add(remote.name);
    const local = builtinByName.get(remote.name);
    if (!local) { merged.push(remote); continue; }
    merged.push(Object.assign({}, remote, {
      keywords: dedupeStrings([].concat(local.keywords || [], remote.keywords || [])),
      officialDomains: dedupeStrings([].concat(local.officialDomains || [], remote.officialDomains || [])),
      trustedDomains: dedupeStrings([].concat(local.trustedDomains || [], remote.trustedDomains || [])),
      officialUrls: dedupeStrings([].concat(local.officialUrls || [], remote.officialUrls || []))
    }));
  }
  // 内置独有品牌追加
  for (const local of builtinBrands) {
    if (!seenNames.has(local.name)) merged.push(local);
  }
  return merged;
}

// 品牌规则结构校验：存在脏数据则放弃整源（保证评分引擎稳定）
function isValidBrandRule(rule) {
  return rule && typeof rule.name === 'string' && Array.isArray(rule.keywords) &&
    Array.isArray(rule.officialDomains) && Array.isArray(rule.officialUrls) &&
    (rule.trustedDomains === undefined || Array.isArray(rule.trustedDomains));
}

// 品牌库刷新（v2.1.3 改造）：内置 brands.json 始终参与合并，远程源提供
// 增量数据；远程全部失败时内置独立兜底。成功后写入 storage 持久化，
// SW 重启可直接恢复，避免每次唤醒都拉远程
async function refreshBrands() {
  try {
    // 1. 加载内置 brands.json（本地打包资源，开销可忽略，永远参与）
    let builtinBrands = [];
    try {
      const builtinResp = await fetchWithTimeout(chrome.runtime.getURL('brands.json'), FETCH_TIMEOUT_MS);
      if (builtinResp.ok) {
        const builtinConfig = await builtinResp.json();
        if (Array.isArray(builtinConfig.brands)) {
          builtinBrands = builtinConfig.brands.filter(isValidBrandRule);
        }
      }
    } catch(e) { /* 内置文件读取异常（理论不可能）：退化为纯远程模式 */ }

    // 2. 拉取远程源并与内置合并
    const brandSources = [BRAND_SOURCE_URL];
    for (let i = 0; i < brandSources.length; i++) {
      try {
        const response = await fetchWithTimeout(brandSources[i], FETCH_TIMEOUT_MS);
        if (!response.ok) continue;
        const config = await response.json();
        if (!Array.isArray(config.brands) || !config.brands.length) continue;
        const validBrands = config.brands.filter(isValidBrandRule);
        if (validBrands.length !== config.brands.length) continue;
        // v2.1.3：内置与远程合并（本地关键词永不丢失）后再应用本地修正
        const merged = mergeBrandConfig(builtinBrands, validBrands);
        const patchedBrands = applyBrandOverrides(merged);
        cache.brandConfig = patchedBrands;
        cache.brandsVer = (chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '';
        await storageSet({ brandConfig: patchedBrands, brandsVer: cache.brandsVer });
        debug('refreshBrands: 加载 ' + patchedBrands.length + ' 个品牌规则（内置 ' +
          builtinBrands.length + ' + 远程合并 via ' + brandSources[i] + '）');
        return { ok: true, count: patchedBrands.length, source: brandSources[i] };
      } catch(e) { /* 保留上一次有效品牌库，尝试下一个源 */ }
    }

    // 3. 远程源全部失败：内置独立兜底（旧逻辑仅内存为空时才回退内置，
    //    远程失败后内存若有旧数据则继续用旧数据——这里改为内置兜底，
    //    保证内置的关键词修正（如 qishui）始终有机会生效）
    if (builtinBrands.length) {
      const patchedBrands = applyBrandOverrides(builtinBrands);
      cache.brandConfig = patchedBrands;
      cache.brandsVer = (chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '';
      await storageSet({ brandConfig: patchedBrands, brandsVer: cache.brandsVer });
      debug('refreshBrands: 远程源不可用，使用内置品牌库 ' + patchedBrands.length + ' 条');
      return { ok: true, count: patchedBrands.length, source: 'builtin' };
    }
  } catch(e) { /* */ }
  console.warn(LOG + 'refreshBrands: 所有品牌源获取失败');
  return { ok: false, count: cache.brandConfig.length };
}

// ===== storage 访问 =====
// MV3 的 chrome.storage.local 原生支持 Promise，无需手写回调包装。
// 写入保留薄封装兜底异常，避免调用处出现未处理的 rejection

async function storageSet(obj) {
  try {
    await chrome.storage.local.set(obj);
    return true;
  } catch(e) {
    console.warn(LOG + 'storage.local.set 失败:', e && e.message);
    return false;
  }
}

// ===== 网络请求 =====

// 带超时的 fetch：防止规则源无响应时长时间挂起
async function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { cache: 'no-store', signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// 解析规则文本为域名数组（过滤空行与注释行）
function parseRuleText(text) {
  return text.split('\n').map(function(l) { return l.trim().toLowerCase(); })
    .filter(function(l) { return l.length > 0 && !l.startsWith('#') && !l.startsWith('//') && l.includes('.'); });
}

// ===== Offscreen 文档管理 =====

// 触发 offscreen 文档拉取远程规则：
// 1) 先关闭旧文档再创建——offscreen 脚本只在文档加载时执行一次，
//    文档常驻时再次刷新不会重新拉取（旧实现的隐患）；
// 2) 通过 runtime 消息回执获取结果，而非依赖 storage.onChanged——
//    规则内容与上次相同时 storage 不触发变更事件，旧实现会白等 15 秒超时
async function fetchViaOffscreen() {
  try {
    try {
      if (await chrome.offscreen.hasDocument()) {
        await chrome.offscreen.closeDocument();
      }
    } catch(e) { /* 无文档可关，忽略 */ }
    await chrome.offscreen.createDocument({
      url: 'offscreen.html', reasons: ['DOM_SCRAPING'],
      justification: '获取远程规则列表'
    });
  } catch(e) {
    console.warn(LOG + 'fetchViaOffscreen: 创建文档失败: ' + e.message);
    return null;
  }
  // 监听 offscreen.js 的回执消息（成功带 domains，失败 ok=false）
  return new Promise(function(resolve) {
    const timer = setTimeout(function() {
      try { chrome.runtime.onMessage.removeListener(listener); } catch(e) {}
      resolve(null);
    }, OFFSCREEN_WAIT_MS);
    function listener(msg) {
      if (!msg || msg.action !== 'offscreenResult') return;
      clearTimeout(timer);
      try { chrome.runtime.onMessage.removeListener(listener); } catch(e) {}
      resolve(msg.ok && msg.domains && msg.domains.length > 0 ? msg.domains : null);
    }
    chrome.runtime.onMessage.addListener(listener);
  });
}

// 直接通过 SW fetch 获取远程规则（利用 host_permissions）
async function fetchViaSW() {
  try {
    for (let i = 0; i < RULE_SOURCE_URLS.length; i++) {
      try {
        const r = await fetchWithTimeout(RULE_SOURCE_URLS[i], FETCH_TIMEOUT_MS);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const text = await r.text();
        const domains = parseRuleText(text);
        if (domains.length > 0) {
          debug('fetchViaSW: 成功获取 ' + domains.length + ' 个域名 (via ' + RULE_SOURCE_URLS[i] + ')');
          return domains;
        }
      } catch(e) { /* try next */ }
    }
  } catch(e) { /* */ }
  console.warn(LOG + 'fetchViaSW: 所有 URL 获取失败');
  return null;
}

// 云白名单拉取：逐行解析，支持完整 URL 或裸域名写法
async function fetchCloudWhitelist() {
  try {
    const r = await fetchWithTimeout(CLOUD_WHITELIST_URL, FETCH_TIMEOUT_MS);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const text = await r.text();
    const domains = text.split('\n').map(function(line) {
      line = line.trim().toLowerCase();
      if (!line || line.startsWith('#') || line.startsWith('//')) return '';
      try {
        if (/^https?:\/\//.test(line)) return new URL(line).hostname.toLowerCase();
      } catch(e) { return ''; }
      return line.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
    }).filter(function(domain) { return domain && domain.includes('.') && !/[\s/?#]/.test(domain); });
    return Array.from(new Set(domains));
  } catch(e) {
    console.warn(LOG + 'fetchCloudWhitelist 失败: ' + e.message);
    return null;
  }
}

// ===== 临时放行（bypass）=====

// v2.1.1 修复（外部审查指出）：cache.bypass 原以完整 URL 为键，而
// installTemporaryAllow 安装的是 host 级 DNR allow 规则——用户在警告页
// 点"继续访问"后，同域名下导航到不同路径时 bypass 未命中，handleNav
// 会再次跳警告页，造成页面反复重定向。现改为按 hostname 记忆放行，
// 与 DNR 会话规则的覆盖范围（host 级）对齐
function markBypassed(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (hostname) cache.bypass[hostname] = Date.now();
  } catch(e) { /* 非法 URL：忽略 */ }
}

// 检查 URL 所属 hostname 是否处于临时放行窗口（10 秒）内
function isRecentlyBypassed(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return !!(hostname && cache.bypass[hostname] &&
      Date.now() - cache.bypass[hostname] < 10000);
  } catch(e) { return false; }
}

// ===== v2.1.3 r3：解冻窗口期（内存级，与 bypass 同模式） =====
// 用户在冻结横幅上确认解冻后，以 hostname 为粒度登记时间戳；窗口期内
// （默认 30 分钟）该站软拦截回执带 unfrozen 标记——content 侧仅注入
// 警示横幅、不再冻结。刷新即恢复完整功能（r3 解冻方案的核心状态）。
// 窗口期有界：到期后同站再次评分达到软拦截线会重新冻结（安全兜底）
const UNFROZEN_WINDOW_MS = 30 * 60 * 1000; // 解冻窗口期：30 分钟

// 登记解冻窗口期（markUnfrozen 消息入口调用）。
// v2.6.0：解冻确认同时写入用户信任记忆（host 级、7 天持久化）——用户看过
// 横幅并主动解除限制，是人工核验过的放行信号，不应随 SW 回收遗忘
function markUnfrozen(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (hostname) {
      cache.unfrozen[hostname] = Date.now();
      markUserTrusted(hostname);
    }
  } catch(e) { /* 非法 URL：忽略 */ }
}

// 检查 URL 所属 hostname 是否处于解冻窗口期内
function isRecentlyUnfrozen(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return !!(hostname && cache.unfrozen[hostname] &&
      Date.now() - cache.unfrozen[hostname] < UNFROZEN_WINDOW_MS);
  } catch(e) { return false; }
}

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

// 为"继续访问/加入白名单"安装 15 秒的 DNR 会话 allow 规则，
// 避免重定向回警告页形成循环
async function installTemporaryAllow(url, tabId) {
  if (!chrome.declarativeNetRequest.updateSessionRules || !tabId) return;
  let hostname;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return;
    hostname = parsed.hostname.toLowerCase();
  } catch(e) { return; }
  const ruleId = 1000000 + tabId;
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [ruleId],
      addRules: [{
        id: ruleId,
        priority: 10,
        action: { type: 'allow' },
        condition: { tabIds: [tabId], requestDomains: [hostname], resourceTypes: ['main_frame'] }
      }]
    });
    setTimeout(function() {
      chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId], addRules: [] }).catch(function() {});
    }, 15000);
  } catch(e) {
    console.warn(LOG + 'installTemporaryAllow 失败: ' + e.message);
  }
}

// ===== DNR 重定向规则 =====
// 使用 action: 'redirect' 替代 'block'，避免 Edge 显示"已阻止 invalid"
// 在 main_frame 导航层直接重定向到警告页，在 SmartScreen/webRequest 之前生效
// 使用 requestDomains（每规则最多 50 域名）避免 regex 2KB 编译限制

let _nextDnrRuleId = 1;  // 全局唯一 ID 计数器，防止并发调用冲突

// 分批安装 DNR 规则，单条失败不回滚全部
async function installDNRRulesGroup(rules, toRemove) {
  if (rules.length === 0) return true;
  // 先删除旧规则（updateDNR 传入全量旧 ID，实现"全量替换"语义，
  // 同时天然清理旧版本残留的 DNR 规则）
  if (toRemove.length > 0) {
    try {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: toRemove, addRules: [] });
    } catch(e) {
      console.warn(LOG + 'installDNRRulesGroup: 清理旧规则失败: ' + e.message);
      return false;
    }
  }
  const batchSize = 200;
  for (let i = 0; i < rules.length; i += batchSize) {
    const batch = rules.slice(i, i + batchSize);
    try {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [],
        addRules: batch
      });
      debug('installDNRRulesGroup: 批次 ' + (i / batchSize + 1) + ' 成功 (' + batch.length + ' 条)');
    } catch(e) {
      console.warn(LOG + 'installDNRRulesGroup: 批次 ' + (i / batchSize + 1) +
        ' 失败: ' + e.message + '，逐条安装');
      for (let j = 0; j < batch.length; j++) {
        try {
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [],
            addRules: [batch[j]]
          });
        } catch(e2) {
          console.warn(LOG + 'installDNRRulesGroup: 规则 ID=' + batch[j].id + ' 跳过: ' + e2.message);
        }
      }
    }
  }
}

// 全量替换 DNR 动态规则（getDynamicRules → 删旧 → 装新，无清理间隙外的中间态）
async function updateDNR() {
  try {
    if (typeof chrome.declarativeNetRequest === 'undefined' ||
        typeof chrome.declarativeNetRequest.getDynamicRules === 'undefined') {
      console.warn(LOG + 'updateDNR: DNR API 不可用');
      return;
    }

    const domains = cache.blocklist || [];
    if (domains.length === 0) {
      // v2.1.1 修复（外部审查指出）：黑名单为空时不能直接返回——
      // 旧规则（上次成功安装的拦截规则）会继续残留生效，造成已清空
      // 黑名单后仍误拦。此处仍需执行一次全量清理再返回
      debug('updateDNR: 黑名单为空，清理全部旧 DNR 规则');
      try {
        const existingEmpty = await chrome.declarativeNetRequest.getDynamicRules();
        if (existingEmpty.length > 0) {
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: existingEmpty.map(function(r) { return r.id; }),
            addRules: []
          });
          debug('updateDNR: 已清理 ' + existingEmpty.length + ' 条残留规则');
        }
      } catch(e) {
        console.warn(LOG + 'updateDNR 空黑名单清理失败: ' + e.message);
      }
      return;
    }

    // 全量替换：当前所有规则 ID 都进入删除列表，
    // 旧版本（v1.0.0 block 规则）残留也会被一并清除
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const toRemove = existing.map(function(r) { return r.id; });
    debug('updateDNR: 当前有 ' + toRemove.length + ' 条规则需清理');

    const redirectUrl = chrome.runtime.getURL('warning.html') + '?dnr=1';
    const rules = [];
    const MAX_DOM_PER_RULE = 50;
    const MAX_RULES = 5000;

    // 全部放行域名（云白名单 + v2.0.0 内置默认白名单 + 用户本地白名单）
    // 使用更高优先级，覆盖黑名单及模式规则
    const allowedDomains = getAllowedDomains();
    for (let wi = 0; wi < allowedDomains.length && rules.length < MAX_RULES - 1; wi += MAX_DOM_PER_RULE) {
      const whiteGroup = allowedDomains.slice(wi, wi + MAX_DOM_PER_RULE);
      rules.push({
        id: _nextDnrRuleId++,
        priority: 3,
        action: { type: 'allow' },
        condition: { requestDomains: whiteGroup, resourceTypes: ['main_frame'] }
      });
    }

    // 每 50 个域名一组，用 requestDomains（非 regex，无 2KB 限制）
    for (let i = 0; i < domains.length && rules.length < MAX_RULES - 1; i += MAX_DOM_PER_RULE) {
      const group = [];
      for (let j = 0; j < MAX_DOM_PER_RULE && (i + j) < domains.length; j++) {
        const domain = String(domains[i + j] || '').toLowerCase().replace(/^\.+|\.+$/g, '');
        // v2.1.0：政府域名全豁免——即使被误收进黑名单数据库，
        // 也不为其生成 DNR 拦截规则
        if (domain && !isGovCn(domain)) group.push(domain); // requestDomains 本身会匹配域名及其子域名
      }
      if (group.length > 0) {
        rules.push({
          id: _nextDnrRuleId++,
          priority: 2,
          action: { type: 'redirect', redirect: { url: redirectUrl } },
          condition: {
            requestDomains: group,
            resourceTypes: ['main_frame']
          }
        });
      }
    }

    // v2.1.0 变更：删除"模式域名正则规则"（主域含连字符的 *.com.cn / *.hl.cn / *.cc）。
    // 原因：模式域名为启发式规则，是误伤事业单位/机关官网的主源；DNR 在请求层
    // 直接重定向会导致页面无法加载，官方标识（CONAC 等）检测彻底没有机会执行。
    // 现改为由 handleNav 的 pattern 延迟决策通道处理：页面加载后 content script
    // 扫描官方标识，有标识放行+注入验证卡片，无标识再拦截（含超时兜底）。
    // 黑名单数据库域名保留 DNR 请求层拦截（高置信度，不参与标识豁免）。

    debug('updateDNR: 生成 ' + rules.length + ' 条重定向规则 (' +
      domains.length + ' 域名)，清除 ' + toRemove.length + ' 条旧规则');

    await installDNRRulesGroup(rules, toRemove);
    debug('updateDNR: DNR 重定向规则安装完成');
    return true;
  } catch(e) {
    console.error(LOG + 'updateDNR 失败: ' + e.message);
    return false;
  }
}

// DNR 更新串行化：storage.onChanged 可能在短时间内连续触发多次更新
// （如 refreshRules 先后写入 cloudWhitelist 与 blocklist），
// 并发执行会互相交错产生重复规则堆积，这里用 Promise 链保证一次只跑一个
let _dnrChain = Promise.resolve();
function scheduleDNRUpdate() {
  _dnrChain = _dnrChain
    .then(function() { return updateDNR(); })
    .catch(function(e) { console.warn(LOG + 'scheduleDNRUpdate: ' + e.message); });
  return _dnrChain;
}

// ===== 规则加载 =====

// 从 storage 恢复缓存（SW 每次唤醒时调用）
async function loadCache() {
  try {
    const r = await chrome.storage.local.get(
      ['blocklist','whitelist','cloudWhitelist','blockedCount','settings','lastRefreshStatus','brandConfig','brandsVer']);
    if (r.blocklist) {
      cache.blocklist = r.blocklist;
      // 合并硬编码域名（始终拦截）
      for (let i = 0; i < HARDCODED_DOMAINS.length; i++) {
        if (cache.blocklist.indexOf(HARDCODED_DOMAINS[i]) === -1) {
          cache.blocklist.push(HARDCODED_DOMAINS[i]);
        }
      }
    }
    if (Array.isArray(r.whitelist)) {
      cache.whitelist = normalizeWhitelist(r.whitelist);
      // 规范化结果与存储不一致时回写（一次性数据清洗）
      if (JSON.stringify(cache.whitelist) !== JSON.stringify(r.whitelist)) {
        await storageSet({ whitelist: cache.whitelist });
      }
    }
    if (r.cloudWhitelist) cache.cloudWhitelist = r.cloudWhitelist;
    if (r.blockedCount) cache.blockedCount = r.blockedCount;
    if (r.settings) cache.enabled = r.settings.enabled !== false;
    if (r.lastRefreshStatus) cache.status = r.lastRefreshStatus;
    // v2.0.0：恢复上次拉取成功的品牌库（避免每次唤醒都请求远程）
    // v2.1.0：恢复时同样应用本地关键词修正——storage 里可能是
    // 旧版本持久化的未修正数据（含过泛关键词），必须打补丁
    if (Array.isArray(r.brandConfig) && r.brandConfig.length) {
      cache.brandConfig = applyBrandOverrides(r.brandConfig);
    }
    // v2.1.3：记录品牌库的生成版本——init 据此判断是否需要立即重新
    // 合并（扩展升级后内置 brands.json 变化，storage 旧缓存必须重算）
    cache.brandsVer = r.brandsVer || '';
    rebuildDomainSets();
  } catch(e) {
    console.warn(LOG + 'loadCache 异常: ' + e.message);
  }
}

// 仅刷新白名单相关缓存（checkPage/blockPage/scorePage 高频路径用）
async function refreshWhitelistCache() {
  const stored = await chrome.storage.local.get(['cloudWhitelist', 'whitelist']);
  if (stored.cloudWhitelist) cache.cloudWhitelist = stored.cloudWhitelist;
  if (Array.isArray(stored.whitelist)) cache.whitelist = normalizeWhitelist(stored.whitelist);
  rebuildDomainSets();
}

// 加载扩展内置的兜底规则文件（远程全部失败时使用）
async function loadBundledRules() {
  try {
    const r = await fetch(chrome.runtime.getURL('default_rules.txt'));
    const text = await r.text();
    const domains = parseRuleText(text);
    if (domains.length > 0) {
      debug('loadBundledRules: 加载 ' + domains.length + ' 个内置域名');
      return domains;
    }
  } catch(e) { /* fallthrough */ }
  // 内置文件为空或加载失败时，返回硬编码域名作为最低兜底
  debug('loadBundledRules: 内置规则为空，使用硬编码兜底');
  return HARDCODED_DOMAINS.slice();
}

// ===== 导航拦截（第二层防护）=====

// 命中黑名单时通过 tabs.update 重定向到警告页
function handleNav(details) {
  const url = details.url;
  if (!url) return;
  // v2.1.0 修复：仅处理主框架导航——iframe 命中 pattern 时若也走此通道，
  // 会把整个宿主 tab 挂起/拦截（宿主页可能完全正常）。iframe 场景由
  // content.js 首屏流程处理（location.replace 只替换 iframe 自身）
  if (details.frameId !== 0) return;

  // v2.1.0：新导航开始时作废旧的 pattern 挂起决策（若本次仍命中 pattern
  // 稍后会重新进入挂起）。对比时忽略 #fragment——同文档锚点跳转不重载
  // 页面，content script 不会重跑，旧挂起必须保留，否则扫描结果上报
  // 时找不到挂起条目导致永不拦截
  if (details.tabId >= 0 && pendingPatternTabs.has(details.tabId)) {
    const oldUrl = pendingPatternTabs.get(details.tabId).url;
    if (String(oldUrl).split('#')[0] !== String(url).split('#')[0]) {
      clearPatternPending(details.tabId);
      debug('handleNav 清理旧 pattern 挂起（新导航）: ' + oldUrl + ' -> ' + url);
    }
  }
  // 跳过扩展自身页面
  try {
    if (url.startsWith(chrome.runtime.getURL(''))) return;
  } catch(e) { /* SW 可能未就绪 */ return; }
  if (/^(about|chrome|edge|data|devtools|blob|javascript):/.test(url)) return;
  if (!url.startsWith('http')) return;
  if (!cache.enabled) { debug('handleNav 跳过（已禁用）: ' + url); return; }
  if (matchesLocalWhitelist(url)) {
    debug('handleNav 跳过（白名单）: ' + url);
    return;
  }

  // 临时放行（"继续访问"后的 10 秒窗口，hostname 级：
  // 同域名站内跳转同样放行，与 DNR 会话 allow 规则范围对齐）
  if (isRecentlyBypassed(url)) {
    debug('handleNav 跳过（临时放行）: ' + url);
    return;
  }

  // 域名匹配（Set 快路径，导航高频调用）
  let matched = false;
  let dbHit = false;          // v2.1.0：是否命中黑名单数据库（确切度最高，原因归属优先于模式）
  let hostname = '';
  try {
    hostname = new URL(url).hostname.toLowerCase();
    if (setMatches(cloudWhitelistSet, hostname)) {
      debug('handleNav 跳过（云白名单）: ' + url);
      return;
    }
    // v2.0.0：内置默认白名单豁免（与 DNR allow 规则保持同一套域名）
    if (isDefaultWhitelisted(hostname)) {
      debug('handleNav 跳过（默认白名单）: ' + url);
      return;
    }
    // v2.1.0：政府域名全豁免（gov.cn 注册受审批管制，拦截误报代价高）
    if (isGovCn(hostname)) {
      debug('handleNav 跳过（gov.cn 政府域名豁免）: ' + url);
      return;
    }
    // v2.1.0：数据库命中单独记录，供警告页"拦截原因"展示；
    // 两者同时命中时归属 database（数据库为已确认恶意源，确切度最高）
    dbHit = setMatches(blocklistSet, hostname);
    matched = dbHit || matchesPatternDomain(hostname);
  } catch(e) { /* */ }

  debug('handleNav url=' + url + ' hostname=' + hostname +
    ' matched=' + matched + ' blocklistLen=' + cache.blocklist.length);

  if (!matched || !details.tabId) return;

  // ---- v2.1.0：pattern（可疑域名特征）延迟决策 ----
  // 模式域名为启发式规则（连字符域名等），是误伤事业单位/机关官网的主源。
  // DNR 已不再对模式域名做请求层拦截（见 updateDNR），此类命中改为：
  //   1. 记入 pendingPatternTabs，等待 content script 扫描页面官方标识
  //      （CONAC 党政机关事业单位标识等）后上报扫描结果
  //   2. 收到 officialBadgeFound → 放行，由 content 侧注入悬浮验证卡片
  //   3. 收到 noBadge（页面加载完成后无标识）→ 立即拦截；
  //      页面加载完成（onCompleted）后 5 秒无上报 → 拦截兜底；
  //      总兜底 60 秒（页面一直没加载完）→ 拦截
  //   4. 导航失败（onErrorOccurred，浏览器层面找不到网页）→ 放弃拦截
  // 代价：无官方标识的恶意模式站暴露窗口延长至页面加载完成（至多 60 秒），
  // 换取事业单位/机关官网零误拦 + 正规站"加载完再决策"的从容体验
  if (!dbHit) {
    debug('handleNav pattern 命中，进入官方标识检测流程: ' + url);
    enterPatternPending(details.tabId, url);
    return;
  }

  // ---- database 命中：立即拦截（高置信度，不参与官方标识豁免）----
  // 防抖：5秒内同一 tab+host 不重复处理
  const tabKey = details.tabId + '_' + hostname;
  if (redirectingTabs[tabKey] && Date.now() - redirectingTabs[tabKey] < 5000) {
    debug('handleNav 防抖跳过 tabId=' + details.tabId);
    return;
  }
  redirectingTabs[tabKey] = Date.now();

  cache.blockedCount++;
  storageSet({ blockedCount: cache.blockedCount });
  updateBadge();

  // v2.1.0：保存拦截记录（含拦截原因）——警告页据 getBlockedUrl 展示"拦截原因"卡片
  saveBlockedPageInfo(details.tabId, {
    url: url, fromUrl: url, reason: 'database', ts: Date.now()
  });

  // v2.1.0 修正：此处不再附加 virus=1——导航拦截仅依据域名黑名单匹配，
  // 并没有"下载病毒"的检测依据；"正在下载病毒"强化文案只属于 resource 路径
  // （content script 实际检测到页面请求恶意资源，拦截记录 reason=resource），
  // 警告页按拦截记录中的 reason 字段判断，与 URL 参数解耦
  const warningUrl = chrome.runtime.getURL('warning.html') +
    '?url=' + encodeURIComponent(url) +
    '&tab=' + details.tabId +
    '&t=' + Date.now();

  debug('handleNav 命中黑名单! tabId=' + details.tabId +
    ' url=' + url + ' 重定向到: ' + warningUrl +
    ' totalBlocked=' + cache.blockedCount);

  // 同步重定向：在页面渲染前跳转
  try {
    chrome.tabs.update(details.tabId, { url: warningUrl }, function() {
      if (chrome.runtime.lastError) {
        console.warn(LOG + 'handleNav tabs.update 失败 tabId=' + details.tabId + ': ' + chrome.runtime.lastError.message);
      } else {
        debug('handleNav tabs.update 成功 tabId=' + details.tabId);
      }
    });
  } catch(e) {
    console.error(LOG + 'handleNav tabs.update 异常: ' + e.message);
  }
}

// ===== v2.1.0：pattern 延迟决策（官方标识检测通道）=====

// pattern 挂起的总兜底时长：页面一直未加载完成（慢站/挂起连接）时的
// 最终决策期限。超过此时长仍未收到扫描结果则执行拦截——
// 防止恶意站故意拖慢加载规避拦截，也防挂起条目无限滞留。
// v2.1.1：60s → 30s（外部审查指出窗口过长）——正常页面的决策实际由
// onCompleted + 5 秒上报窗口（PATTERN_COMPLETED_GRACE）完成，总兜底
// 只针对"一直不触发 onCompleted"的极端场景，30 秒足够区分慢站与死站，
// 且把无标识恶意站的最坏暴露窗口压缩一半
const PATTERN_TOTAL_TIMEOUT = 30000;

// 页面加载完成（webNavigation.onCompleted）后留给 content script 的
// 上报窗口：页面已就绪，正常情况下 load 事件后 content script 会立即
// 完成官方标识扫描并上报 officialBadgeFound/noBadge，窗口内无上报
//（扩展上下文失效等）则拦截兜底
const PATTERN_COMPLETED_GRACE = 5000;

// tabId → { url, timer }：pattern 命中后等待官方标识扫描结果的挂起表
const pendingPatternTabs = new Map();

// 清除 tab 的 pattern 挂起（扫描结果到达 / 导航失败 / tab 关闭时调用）
function clearPatternPending(tabId) {
  const entry = pendingPatternTabs.get(tabId);
  if (entry) {
    clearTimeout(entry.timer);
    pendingPatternTabs.delete(tabId);
  }
}

// （重新）武装挂起定时器：超时仍未收到扫描结果则执行拦截兜底。
// enterPatternPending / patternAlive / onCompleted 共用
function armPatternTimer(tabId, url, ms) {
  const entry = pendingPatternTabs.get(tabId);
  if (!entry) return;                        // 已被扫描结果清除则无需再计时
  clearTimeout(entry.timer);
  entry.timer = setTimeout(function() {
    const cur = pendingPatternTabs.get(tabId);
    pendingPatternTabs.delete(tabId);
    if (cur && cur.url === url) executePatternBlock(tabId, url);
  }, ms);
}

// pattern 命中进入挂起：同 tab 重复导航（重定向链）直接刷新挂起条目。
// v2.1.0 更新：不设短超时——拦截决策等页面加载完成（onCompleted 后的
// 上报窗口），加载期间页面保持可见；总兜底见 PATTERN_TOTAL_TIMEOUT
function enterPatternPending(tabId, url) {
  const prev = pendingPatternTabs.get(tabId);
  if (prev) clearTimeout(prev.timer);
  pendingPatternTabs.set(tabId, { url: url, timer: null });
  armPatternTimer(tabId, url, PATTERN_TOTAL_TIMEOUT);
}

// 执行 pattern 拦截跳转（noBadge 确认或超时触发）：
// 保存拦截记录 + 计数 + 重定向警告页（带 tab 参数，警告页可读取完整记录）
function executePatternBlock(tabId, url) {
  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch(e) { /* */ }
  const tabKey = tabId + '_' + hostname;
  if (redirectingTabs[tabKey] && Date.now() - redirectingTabs[tabKey] < 5000) return;
  redirectingTabs[tabKey] = Date.now();

  cache.blockedCount++;
  storageSet({ blockedCount: cache.blockedCount });
  updateBadge();
  saveBlockedPageInfo(tabId, { url: url, fromUrl: url, reason: 'pattern', ts: Date.now() });

  const warningUrl = chrome.runtime.getURL('warning.html') +
    '?url=' + encodeURIComponent(url) + '&tab=' + tabId + '&t=' + Date.now();
  debug('pattern 拦截生效 tabId=' + tabId + ' url=' + url);
  try {
    // 跳转前双重校验，只拦"确实还停在挂起域名上"的 tab：
    // 1. tab 已在警告页（其他拦截路径先命中）则不重复跳转；
    // 2. tab 当前实际域名与挂起域名一致才跳——挂起期间用户可能已通过
    //    pushState/历史导航去了别的页面，时序错位时不得把无关页面送进
    //    警告页；浏览器错误页（chrome-error://，找不到网页）hostname
    //    解析为空同样不匹配，自然跳过（页面都没出来，无需拦截）
    chrome.tabs.get(tabId, function(tab) {
      if (chrome.runtime.lastError || !tab) return;
      if (tab.url && tab.url.startsWith(chrome.runtime.getURL('warning.html'))) return;
      let curHost = '', wantHost = '';
      try { curHost = new URL(tab.url || '').hostname.toLowerCase(); } catch(e) { return; }
      try { wantHost = new URL(url).hostname.toLowerCase(); } catch(e) { return; }
      if (!curHost || curHost !== wantHost) {
        debug('pattern 拦截放弃：tab 已不在挂起域名上（当前 ' + curHost + '，挂起 ' + wantHost + '）');
        return;
      }
      chrome.tabs.update(tabId, { url: warningUrl }, function() { void chrome.runtime.lastError; });
    });
  } catch(e) { /* */ }
}

// ===== 主世界拦截器注入（第三层防护）=====

// 通过 scripting API 注入拦截器到页面主世界（同步注入，绕过 CSP）
// 注意：func 会序列化后注入页面，不能引用外部变量，内部逻辑必须自包含
function injectInterceptor(tabId) {
  // v2.1.1 修复：增加总开关检查——扩展被禁用后不得再向页面注入
  // 主世界拦截器（否则禁用状态下 fetch/XHR 仍被拦截，开关形同虚设）
  if (!cache.enabled) {
    debug('injectInterceptor 跳过 tabId=' + tabId + ' 扩展已禁用');
    return;
  }
  if (!cache.blocklist || cache.blocklist.length === 0) {
    debug('injectInterceptor 跳过 tabId=' + tabId + ' 黑名单为空');
    return;
  }
  try {
    debug('injectInterceptor 注入到 tabId=' + tabId + ' domains=' + cache.blocklist.length);
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      world: 'MAIN',
      injectImmediately: true,
      func: function(domains, allowedDomains, extId) {
        let _reported = false;
        function isListed(hostname, list) {
          for (let i = 0; i < list.length; i++) {
            const domain = String(list[i] || '').toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
            if (domain && (hostname === domain || hostname.endsWith('.' + domain))) return true;
          }
          return false;
        }
        // 页面自身在放行列表（云白名单/默认白名单/用户白名单）中则完全跳过
        const pageAllowed = isListed(location.hostname.toLowerCase(), allowedDomains);
        function isBlockedUrl(url) {
          if (pageAllowed) return false;
          let hostname;
          try { hostname = new URL(url, location.href).hostname.toLowerCase(); } catch(e) { return false; }
          if (isListed(hostname, allowedDomains)) return false;
          // v2.1.0：政府域名全豁免
          if (hostname === 'gov.cn' || hostname.endsWith('.gov.cn')) return false;
          // v2.1.2 变更：移除 51.la SDK 单特征拦截——51.la 是正规统计服务，
          // 数十万正规网站在用同一脚本（误报治理，与 content.js 第二阶段
          // 移除保持一致）；51.la 保留为评分引擎 resource 类指标参与综合裁决
          // v2.1.0 变更：移除"可疑域名模式"检测（连字符 *.com.cn/*.hl.cn/*.cc）——
          // pattern 域名的页面加载自身资源会立即触发 blockPage 拦截，
          // 导致官方标识（CONAC 等）检测彻底失去机会（事业单位官网主误报源）。
          // pattern 检测统一移交 handleNav 的延迟决策通道处理。
          // 此处仅保留高置信度特征：黑名单数据库域名请求。
          for (let i = 0; i < domains.length; i++) {
            const domain = String(domains[i] || '').toLowerCase().replace(/^\.+|\.+$/g, '');
            if (domain && (hostname === domain || hostname.endsWith('.' + domain))) return true;
          }
          return false;
        }
        function block(url) {
          if (!isBlockedUrl(url)) return false;
          if (!_reported) {
            _reported = true;
            // dispatchEvent 通知 ISOLATED world → background → tabs.update
            window.dispatchEvent(new CustomEvent('__yh_block', {
              detail: { url: url, page: location.href, extId: extId }
            }));
          }
          return true;
        }
        const _f = window.fetch;
        window.fetch = function(input) {
          const url = (typeof input === 'string') ? input : (input && input.url ? input.url : '');
          if (block(url)) return Promise.reject(new Error('Blocked'));
          return _f.apply(this, arguments);
        };
        const _o = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
          const u = (typeof url === 'string') ? url : (url ? url.toString() : '');
          if (block(u)) throw new Error('Blocked');
          return _o.apply(this, arguments);
        };
      },
      args: [cache.blocklist, getAllowedDomains(), chrome.runtime.id]
    }).catch(function(err) {
      if (/No tab with id|extensions gallery cannot be scripted/i.test(err.message || '')) return;
      console.warn(LOG + 'injectInterceptor 注入失败 tabId=' + tabId + ': ' + err.message);
    });
  } catch(e) { console.error(LOG + 'injectInterceptor 异常 tabId=' + tabId + ': ' + e.message); }
}

// 向所有标签页的内容脚本广播最新黑名单（规则更新时调用）
function broadcastBlocklist() {
  const list = cache.blocklist;
  try {
    chrome.tabs.query({}, function(tabs) {
      for (let i = 0; i < tabs.length; i++) {
        try {
          chrome.tabs.sendMessage(tabs[i].id, {
            action: 'updateBlocklist', domains: list, cloudWhitelist: cache.cloudWhitelist
          }, function() {
            void chrome.runtime.lastError; // 吞掉 "Could not establish connection" 错误
          });
        } catch(e) { /* */ }
      }
    });
  } catch(e) { /* */ }
}

// ===== 拦截记录持久化（v2.0.0 新增）=====

// 拦截时同时写入内存 Map 与 storage（key: blockedPage_<tabId>）。
// SW 可能被随时终止，警告页打开时若内存已丢失则从 storage 恢复评分明细
// v2.1.1：同步维护 storage 键索引（_blockedPageKeys），供
// cleanupExpiredBlockedPages 做增量清理，避免每 30 秒 get(null) 全量拉取
function saveBlockedPageInfo(tabId, info) {
  blockedPageUrls.set(tabId, info);
  _blockedPageKeys.add('blockedPage_' + tabId);
  storageSet({ ['blockedPage_' + tabId]: info });
}

// 已写入 storage 的拦截记录键索引（v2.1.1 新增）：
// chrome.storage 不支持前缀查询，get(null) 会拉全部数据（含上万条
// 黑名单域名），keepAlive 每 30 秒全量拉一次开销不小。这里改为：
//   - SW 生命周期内首次清理：get(null) 兜底扫描（回收上次生命周期残留）
//     并把未过期键收编进索引
//   - 之后每次：只按索引中的键增量 get，过期的 remove 并移出索引
let _blockedPageKeys = new Set();
let _didFullStorageScan = false;

// 清理 storage 中过期的拦截记录（keepAlive 定时调用）：
// 5 分钟内未被警告页消费的记录直接删除，防止 storage 无限膨胀
async function cleanupExpiredBlockedPages(now) {
  try {
    const expired = [];
    if (!_didFullStorageScan) {
      // SW 唤醒后首次：全量扫描，顺带收编残留的未过期键
      _didFullStorageScan = true;
      const all = await chrome.storage.local.get(null);
      for (const key of Object.keys(all)) {
        if (!key.startsWith('blockedPage_')) continue;
        const info = all[key];
        if (!info || !info.ts || now - info.ts > 300000) expired.push(key);
        else _blockedPageKeys.add(key);
      }
    } else if (_blockedPageKeys.size > 0) {
      // 增量路径：只取索引内的键，不再全量拉取
      const stored = await chrome.storage.local.get([..._blockedPageKeys]);
      for (const key of Object.keys(stored)) {
        const info = stored[key];
        if (!info || !info.ts || now - info.ts > 300000) expired.push(key);
      }
    }
    if (expired.length > 0) {
      await chrome.storage.local.remove(expired);
      for (const key of expired) _blockedPageKeys.delete(key);
    }
  } catch(e) { /* */ }
}

// ===== 规则刷新 =====

async function refreshRules() {
  debug('refreshRules 开始...');
  try {
    // 0. 品牌库（v2.0.0 新增，失败不阻塞主流程）
    await refreshBrands();
    // 1. 云白名单（失败不阻塞主流程）
    const cloudWhitelist = await fetchCloudWhitelist();
    if (cloudWhitelist) {
      cache.cloudWhitelist = cloudWhitelist;
      await storageSet({ cloudWhitelist: cloudWhitelist, cloudWhitelistLastRefresh: Date.now() });
      rebuildDomainSets();
    }
    // 2. 黑名单：offscreen 优先 → SW fetch → 内置兜底
    let result = await fetchViaOffscreen();
    if (!result) {
      debug('refreshRules offscreen 获取失败，尝试 SW fetch');
      result = await fetchViaSW();
    }
    if (!result) {
      debug('refreshRules 远程获取全部失败，回退到内置规则');
      const bundled = await loadBundledRules();
      if (bundled) {
        cache.blocklist = bundled;
        cache.status = 'bundled';
        await storageSet({ blocklist: bundled, lastRefresh: Date.now(), lastRefreshStatus: 'bundled' });
        debug('refreshRules 加载内置规则: ' + bundled.length + ' 个域名');
      }
    } else {
      debug('refreshRules 远程规则加载成功: ' + result.length + ' 个域名');
      cache.blocklist = result;
      cache.status = 'remote';
      await storageSet({ blocklist: result, lastRefresh: Date.now(), lastRefreshStatus: 'remote' });
    }
    // 确保硬编码高危域名始终在黑名单中
    for (let hi = 0; hi < HARDCODED_DOMAINS.length; hi++) {
      if (cache.blocklist.indexOf(HARDCODED_DOMAINS[hi]) === -1) {
        cache.blocklist.push(HARDCODED_DOMAINS[hi]);
      }
    }
    rebuildDomainSets();
    updateBadge();
    // 规则更新后同步替换 DNR（全量替换语义，无清理间隙）。
    // v2.1.1：改走 scheduleDNRUpdate 串行链，与其他更新源统一排队
    try { await scheduleDNRUpdate(); } catch(e) { console.error(LOG + 'refreshRules updateDNR 异常: ' + e.message); }
  } catch(e) { console.error(LOG + 'refreshRules 异常: ' + e.message); }
}

// ===== 徽标 =====

// v2.1.0：按需求移除浏览器工具栏图标上的徽标
//（不再显示累计拦截次数与规则未就绪的 '!' 提示，保持图标干净）。
// 保留函数与全部调用点以兼容既有流程，这里仅负责把徽标清空
async function updateBadge() {
  try {
    // 清空徽标文字即为移除徽标；底色设置保留无害，但已无可见效果
    await chrome.action.setBadgeText({ text: '' });
  } catch(e) { /* */ }
}

// ===== 初始化 =====

// init 互斥（v2.1.1 稳定性修复）：init() 在顶层、onInstalled、onStartup
// 三处被调用，SW 单次生命周期内可能并发触发多次（如安装事件与顶层执行
// 竞争）。并发 init 会导致 updateDNR 交错执行（规则重复/误删）、
// loadCache 与 bundled 规则写入互相覆盖。这里缓存首次执行的 Promise，
// 后续调用直接复用同一实例，保证单次 SW 生命周期内只初始化一次
let _initPromise = null;
function initOnce() {
  if (!_initPromise) _initPromise = init().catch(function(e) {
    // 初始化失败时清除缓存，允许下次事件（如 onStartup）重试
    _initPromise = null;
    console.error(LOG + 'init 失败: ' + e.message);
  });
  return _initPromise;
}

async function init() {
  debug('init() 开始，SW 运行时: ' + (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id || 'unknown'));
  try { await loadCache(); } catch(e) { console.error(LOG + 'init loadCache 异常: ' + e.message); }
  debug('init 缓存加载完成: blocklist=' + (cache.blocklist ? cache.blocklist.length : 0) +
    ' whitelist=' + cache.whitelist.length + ' blockedCount=' + cache.blockedCount +
    ' brands=' + cache.brandConfig.length);
  // storage 为空（首次安装/规则被清）时加载内置兜底规则
  if (!cache.blocklist || cache.blocklist.length === 0) {
    const bundled = await loadBundledRules();
    if (bundled) {
      cache.blocklist = bundled; cache.status = 'bundled';
      await storageSet({ blocklist: bundled, lastRefresh: Date.now(), lastRefreshStatus: 'bundled' });
      debug('init 加载内置规则: ' + bundled.length + ' 个域名');
    }
  }
  try {
    // initialFetch：唤醒后 3 秒拉取远程规则；refreshBlocklist：每小时定时刷新
    chrome.alarms.create('initialFetch', { delayInMinutes: 0.05 });
    chrome.alarms.create('keepAlive', { periodInMinutes: 0.5 });
    debug('init 定时器已创建');
  } catch(e) { debug('init 创建定时器异常: ' + e.message); }
  updateBadge();
  // 确保硬编码高危域名始终在黑名单中（远程规则可能没包含它们）
  for (let hi = 0; hi < HARDCODED_DOMAINS.length; hi++) {
    if (cache.blocklist.indexOf(HARDCODED_DOMAINS[hi]) === -1) {
      cache.blocklist.push(HARDCODED_DOMAINS[hi]);
      debug('init 补充硬编码域名: ' + HARDCODED_DOMAINS[hi]);
    }
  }
  rebuildDomainSets();
  // v2.0.0：品牌库为空时立即拉取（首次安装/升级场景，评分引擎依赖品牌配置）
  // v2.1.3：升级场景同样立即刷新——storage 里可能存着旧版本生成的品牌缓存
  //（曾含被远程覆盖丢失 "qishui" 关键词的污染数据），版本标记不一致时
  // 重新执行"内置 + 远程"合并，不等 3 秒后的 initialFetch 定时器
  const currentVer = (chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '';
  if (!cache.brandConfig || cache.brandConfig.length === 0 ||
      (currentVer && cache.brandsVer !== currentVer)) {
    debug('init 品牌库需刷新（空库或版本变更 ' + cache.brandsVer + ' → ' + currentVer + '）');
    refreshBrands();
  }
  // 全量替换 DNR 规则（自带旧规则清理，无需单独的清空步骤，
  // 避免了"先清空再重建"之间的漏拦间隙）。
  // v2.1.1：改走 scheduleDNRUpdate 串行链——与 storage.onChanged 触发的
  // 更新统一排队，杜绝两条链路并发执行 updateDNR 造成规则交错
  try { await scheduleDNRUpdate(); } catch(e) { console.error(LOG + 'init updateDNR 异常: ' + e.message); }
  debug('init() 完成');
}

// ===== 事件监听 =====

// 无过滤全局监听：记录所有导航事件（排查 onBeforeNavigate 是否正常触发）
chrome.webNavigation.onBeforeNavigate.addListener(function(details) {
  if (details.frameId === 0 && details.tabId >= 0 && /^https?:\/\//.test(details.url || '')) {
    lastNavigationUrls.set(details.tabId, details.url);
    // 修剪：超过 300 条时删掉最旧的 200 条，防止内存无限增长
    if (lastNavigationUrls.size > 300) {
      let removed = 0;
      for (const key of lastNavigationUrls.keys()) {
        if (removed++ >= 200) break;
        lastNavigationUrls.delete(key);
      }
    }
  }
  debug('RAW onBeforeNavigate frameId=' + details.frameId +
    ' tabId=' + details.tabId +
    ' parentFrameId=' + details.parentFrameId +
    ' url=' + details.url +
    ' timeStamp=' + details.timeStamp);
});

// 仅用 onBeforeNavigate 做导航拦截（onCommitted 已太晚）
chrome.webNavigation.onBeforeNavigate.addListener(handleNav, { url: [{ urlMatches: 'https?://.*' }] });

// ===== v2.1.0：pattern 延迟决策的页面生命周期事件 =====

// 页面加载完成：对挂起中的 pattern tab 启动短上报窗口——
// 页面已就绪，content script 将在 load 事件后完成官方标识扫描并上报
// （officialBadgeFound / noBadge），窗口内无上报则拦截兜底
chrome.webNavigation.onCompleted.addListener(function(details) {
  if (details.frameId !== 0 || details.tabId < 0) return;
  const entry = pendingPatternTabs.get(details.tabId);
  if (entry) {
    armPatternTimer(details.tabId, entry.url, PATTERN_COMPLETED_GRACE);
    debug('onCompleted 页面加载完成，pattern 决策窗口开启 tabId=' + details.tabId);
  }
}, { url: [{ urlMatches: 'https?://.*' }] });

// 导航失败（DNS 解析失败/连接拒绝等浏览器层面错误）：
// 页面根本没有出来，无需也无法拦截，直接作废挂起决策
chrome.webNavigation.onErrorOccurred.addListener(function(details) {
  if (details.frameId !== 0 || details.tabId < 0) return;
  if (pendingPatternTabs.has(details.tabId)) {
    debug('onErrorOccurred 导航失败，放弃 pattern 拦截 tabId=' + details.tabId +
      ' error=' + details.error);
    clearPatternPending(details.tabId);
  }
});

// tab 关闭：清理挂起条目，防止定时器残留与内存泄漏
chrome.tabs.onRemoved.addListener(function(tabId) {
  if (pendingPatternTabs.has(tabId)) clearPatternPending(tabId);
});

// 页面加载时注入拦截器到主世界
chrome.webNavigation.onCommitted.addListener(function(details) {
  if (details.frameId !== 0) return;
  if (!details.url || !details.url.startsWith('http')) return;
  // 浏览器扩展商店页面禁止注入，直接跳过
  if (/^https:\/\/(?:microsoftedge\.microsoft\.com\/addons|chromewebstore\.google\.com\/|chrome\.google\.com\/webstore)/i.test(details.url)) return;
  debug('onCommitted tabId=' + details.tabId + ' url=' + details.url);
  chrome.storage.local.get(['blocklist', 'cloudWhitelist', 'whitelist']).then(function(stored) {
    // v2.1.1 修复：blocklist 覆盖后必须重新合并硬编码域名——
    // 若 storage 中的列表不含硬编码高危域名（如被外部写入），
    // 直接覆盖会让兜底拦截失效（与 loadCache/storage.onChanged 同步修复）
    if (stored.blocklist) {
      cache.blocklist = stored.blocklist;
      for (let hi = 0; hi < HARDCODED_DOMAINS.length; hi++) {
        if (cache.blocklist.indexOf(HARDCODED_DOMAINS[hi]) === -1) {
          cache.blocklist.push(HARDCODED_DOMAINS[hi]);
        }
      }
    }
    if (stored.cloudWhitelist) cache.cloudWhitelist = stored.cloudWhitelist;
    if (Array.isArray(stored.whitelist)) cache.whitelist = normalizeWhitelist(stored.whitelist);
    rebuildDomainSets();
    let hostname = '';
    try { hostname = new URL(details.url).hostname.toLowerCase(); } catch(e) { return; }
    // v2.0.0：放行列表含内置默认白名单。
    // v2.1.1：改用预构建合并集 allAllowedSet（rebuildDomainSets 时更新），
    // 替代每次导航现场调 getAllowedDomains() 合并数组 + 线性扫描
    if (setMatches(allAllowedSet, hostname)) return;
    injectInterceptor(details.tabId);
  });
}, { url: [{ urlMatches: 'https?://.*' }] });

// 定时器：规则拉取 + SW 保活与缓存清理
chrome.alarms.onAlarm.addListener(function(alarm) {
  if (alarm.name === 'initialFetch' || alarm.name === 'refreshBlocklist') {
    refreshRules();
    // 首次唤醒后建立每小时的循环刷新
    if (alarm.name === 'initialFetch') {
      try { chrome.alarms.create('refreshBlocklist', { periodInMinutes: 60 }); } catch(e) {}
    }
  } else if (alarm.name === 'keepAlive') {
    const now = Date.now();
    // 清理过期的临时放行与防抖记录，防止内存无限增长
    for (const k in cache.bypass) { if (now - cache.bypass[k] > 30000) delete cache.bypass[k]; }
    for (const rk in redirectingTabs) { if (now - redirectingTabs[rk] > 30000) delete redirectingTabs[rk]; }
    // 清理 5 分钟前写入、未被 warning 页消费的拦截记录（内存 + storage）
    for (const [bpKey, bpVal] of blockedPageUrls) {
      if (now - (bpVal.ts || 0) > 300000) blockedPageUrls.delete(bpKey);
    }
    cleanupExpiredBlockedPages(now);
    loadCache().then(function() { updateBadge(); });
  }
});

// storage 变化同步内存缓存，并联动 DNR 与内容脚本广播
try {
  chrome.storage.onChanged.addListener(function(changes) {
    if (changes.blocklist && changes.blocklist.newValue) {
      // v2.1.1 修复（外部审查指出）：直接覆盖会丢失硬编码高危域名——
      // 若外部（如 popup 或未来版本）写入的列表未包含它们，兜底拦截
      // 将失效。覆盖后统一重新合并（与 loadCache/onCommitted 同步修复）
      cache.blocklist = changes.blocklist.newValue;
      for (let hi = 0; hi < HARDCODED_DOMAINS.length; hi++) {
        if (cache.blocklist.indexOf(HARDCODED_DOMAINS[hi]) === -1) {
          cache.blocklist.push(HARDCODED_DOMAINS[hi]);
        }
      }
      debug('storage.onChanged blocklist 更新: ' + cache.blocklist.length + ' 域名');
      rebuildDomainSets();
      // 同步替换 DNR 重定向规则（串行化，防并发交错）
      scheduleDNRUpdate();
      // 通知所有内容脚本更新黑名单
      broadcastBlocklist();
    }
    if (changes.whitelist) {
      cache.whitelist = normalizeWhitelist(changes.whitelist.newValue || []);
      rebuildDomainSets();
      scheduleDNRUpdate();
    }
    if (changes.cloudWhitelist && changes.cloudWhitelist.newValue) {
      cache.cloudWhitelist = changes.cloudWhitelist.newValue;
      rebuildDomainSets();
      scheduleDNRUpdate();
      broadcastBlocklist();
    }
    if (changes.lastRefreshStatus && changes.lastRefreshStatus.newValue) {
      cache.status = changes.lastRefreshStatus.newValue;
    }
    // v2.0.0：品牌库更新（如 popup 触发的手动刷新）同步内存缓存
    // v2.1.0：同步时应用本地关键词修正（写入方可能是未打补丁的旧路径）
    if (changes.brandConfig && Array.isArray(changes.brandConfig.newValue)) {
      cache.brandConfig = applyBrandOverrides(changes.brandConfig.newValue);
    }
  });
} catch(e) { /* */ }

// ===== v2.3.0：AI 对话页外链核查（沙箱防追踪探测）=====
// 对话中由 AI 给出的链接可能是幻觉域名/钓鱼站/被入侵站。分级策略：
//   danger  已知恶意（内置投毒库/黑名单命中；或探测后发现重定向落地恶意域）
//   warn    可疑（多信号可疑形态，探测后附探测结论）
//   safe    官方/白名单/政府域
//   unknown 无已知风险且未探测——不对干净外链发请求，避免无谓网络行为
// v2.3.2：探测触发从单一"连字符模式"扩展为多信号（见
// aiLinkSuspicionReasons）：高滥用 TLD / http 明文 / IP 直连 / punycode /
// 非 ASCII 域名 / 注册标签含连字符 / 深子域 / 超长主机名，命中任一即探测。
// v2.3.3：域名品牌词仿冒（aiLinkBrandImpersonation，含编辑距离 ≤1 变体）
// 同样纳入触发，且置于原因首位。
// v2.3.4：疑似仿冒不再直接定可疑——转入第二阶段 ICP 备案核验裁决
//（verifyIcpForAiLink）：有有效备案 → 嫌疑解除；查无备案 → 仿冒坐实。
// 核验期间回执 pendingIcp 过渡态，终局结论经 aiLinkVerdict 推回标签页。
// 探测全程防追踪：
//   credentials:'omit'          不携带任何 Cookie/凭证
//   referrerPolicy:'no-referrer' 不泄露来源页（对话内容不出本机）
//   cache:'no-store'            不读写 HTTP 缓存
//   不读取响应体                 仅取最终 URL 与状态码
const _aiLinkVerdictCache = new Map();        // url → { verdict, ts }
const AI_LINK_CACHE_TTL_MS = 30 * 60 * 1000;  // 结论缓存 30 分钟
const AI_LINK_CACHE_MAX = 300;
// v2.7.0：AI_LINK_PROBE_TIMEOUT_MS 已随沙箱探测抽取至 modules/sandbox-probe.js
const AI_LINK_BATCH_MAX = 20;
// v2.3.6：缓存持久化到 chrome.storage.session——此前 Map 只活在 SW 内存，
// MV3 的 Service Worker 空闲 ~30 秒即被回收，页面一刷新缓存就空了，
// 每次都要重新探测/查备案。storage.session 在整个浏览器会话内存续
//（SW 重启不丢、不落磁盘、关闭浏览器即清除，隐私上适合存核查记录），
// 写入做 1 秒防抖合并；读取在首次核查前异步灌回内存 Map
const AI_LINK_CACHE_STORAGE_KEY = 'aiLinkVerdictCache';
let _verdictStoreLoaded = false;
let _verdictStoreLoadPromise = null;
let _verdictFlushTimer = null;

function ensureVerdictStoreLoaded() {
  if (_verdictStoreLoaded) return Promise.resolve();
  if (_verdictStoreLoadPromise) return _verdictStoreLoadPromise;
  _verdictStoreLoadPromise = new Promise(function(resolve) {
    try {
      chrome.storage.session.get(AI_LINK_CACHE_STORAGE_KEY, function(data) {
        try {
          const arr = data && data[AI_LINK_CACHE_STORAGE_KEY];
          if (Array.isArray(arr)) {
            for (const pair of arr) {
              if (pair && typeof pair.url === 'string' && pair.verdict && pair.ts &&
                  Date.now() - pair.ts <= AI_LINK_CACHE_TTL_MS) {
                _aiLinkVerdictCache.set(pair.url, { verdict: pair.verdict, ts: pair.ts });
              }
            }
          }
        } catch(e) { /* 损坏数据弃用即可 */ }
        _verdictStoreLoaded = true;
        resolve();
      });
    } catch(e) {
      // storage.session 不可用（旧浏览器）：静默退回纯内存模式
      _verdictStoreLoaded = true;
      resolve();
    }
  });
  return _verdictStoreLoadPromise;
}

function flushVerdictStore() {
  if (_verdictFlushTimer) return;
  _verdictFlushTimer = setTimeout(function() {
    _verdictFlushTimer = null;
    try {
      const arr = [];
      for (const [u, hit] of _aiLinkVerdictCache) arr.push({ url: u, verdict: hit.verdict, ts: hit.ts });
      const obj = {};
      obj[AI_LINK_CACHE_STORAGE_KEY] = arr;
      chrome.storage.session.set(obj, function() { void chrome.runtime.lastError; });
    } catch(e) { /* */ }
  }, 1000);
}

function getCachedAiLinkVerdict(url) {
  const hit = _aiLinkVerdictCache.get(url);
  if (!hit) return null;
  if (Date.now() - hit.ts > AI_LINK_CACHE_TTL_MS) { _aiLinkVerdictCache.delete(url); return null; }
  return hit.verdict;
}

function cacheAiLinkVerdict(url, verdict) {
  _aiLinkVerdictCache.set(url, { verdict: verdict, ts: Date.now() });
  if (_aiLinkVerdictCache.size > AI_LINK_CACHE_MAX) {
    _aiLinkVerdictCache.delete(_aiLinkVerdictCache.keys().next().value);
  }
  flushVerdictStore();
  return verdict;
}

function isHardcodedHost(hostname) {
  return HARDCODED_DOMAINS.indexOf(hostname) !== -1 ||
    HARDCODED_DOMAINS.some(function(d) { return hostname.endsWith('.' + d); });
}

// v2.3.2：可疑形态多信号判定——此前仅"连字符 com.cn/hl.cn/cc 模式"触发
// 沙箱探测，实测普通钓鱼域（.top/.xyz 新注册、http 明文、IP 直连、深子域等）
// 全部落灰不查，用户误以为核查通道没生效。扩展为命中任一信号即探测；
// 探测本身防追踪（无 Cookie/无 Referer/不读响应体）且结论缓存 30 分钟，
// 成本可控。返回触发原因数组（空数组 = 不可疑）
const AI_LINK_RISKY_TLDS = [
  'top', 'xyz', 'cc', 'icu', 'cyou', 'buzz', 'monster', 'rest', 'fit', 'live'
];
function aiLinkSuspicionReasons(hostname) {
  const reasons = [];
  if (matchesPatternDomain(hostname)) reasons.push('可疑连字符域名模式');
  const parts = hostname.split('.');
  const tld = parts.length >= 2 ? parts[parts.length - 1] : '';
  if (AI_LINK_RISKY_TLDS.indexOf(tld) !== -1) {
    reasons.push('高滥用 TLD（.' + tld + '）');
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) reasons.push('IP 地址直连');
  if (hostname.indexOf('xn--') !== -1) reasons.push('国际化域名编码（punycode）');
  // 非 ASCII 主机名（同源 Unicode 形态的国际化域名）
  if (/[^\x00-\x7F]/.test(hostname)) reasons.push('含非 ASCII 字符域名');
  // 注册标签含连字符（如 foo-bar.net；pattern 模式已覆盖的不重复记）
  const reg = parts.length >= 2 ? parts[parts.length - 2] : '';
  if (reg && reg.indexOf('-') !== -1 && reasons.indexOf('可疑连字符域名模式') === -1) {
    reasons.push('注册标签含连字符');
  }
  if (parts.length >= 4) reasons.push('深层子域（≥4 级）');
  if (hostname.length > 30) reasons.push('超长主机名');
  return reasons;
}

// v2.3.3：链接侧品牌仿冒判定——AI 给出的链接若域名含某品牌英文关键词
// （或注册标签与关键词编辑距离 ≤1，覆盖 huorrong 双写 r 类拼写变体），
// 却不在该品牌的官方/可信域上，即为典型 typosquatting 特征。
// 与 applyBrandCheck 同一套两遍扫描口径：第一遍官方/可信域全量放行，
// 第二遍才取第一个命中品牌，防止正版站被前面品牌的关键词短路误判。
// 链接侧无页面标题可比，仅做域名维度判定（页面维度由 scorePage 覆盖）。
// 返回命中的品牌名（未命中返回 null）
function aiLinkBrandImpersonation(hostname) {
  if (!Array.isArray(cache.brandConfig) || !cache.brandConfig.length) return null;
  const hostMatchesDomain = function(domain) {
    domain = String(domain).toLowerCase();
    return hostname === domain || hostname.endsWith('.' + domain);
  };
  const onOfficialSite = cache.brandConfig.some(function(rule) {
    return (rule.officialDomains || []).some(hostMatchesDomain) ||
      (rule.trustedDomains || []).some(hostMatchesDomain);
  });
  if (onOfficialSite) return null;
  let hitBrand = null;
  // v2.3.9：注册段提取提升到循环外；短词走强边界（cline.bot 不再命中 LINE）
  const labels = hostname.split('.');
  const second = labels.length >= 2 ? labels[labels.length - 2] : '';
  const isCnDouble = labels[labels.length - 1] === 'cn' &&
    ['com','net','org','gov','edu','ac'].includes(second);
  const cut = isCnDouble ? 2 : 1;
  const registrable = labels.length > cut ? labels[labels.length - cut - 1] : labels[0] || '';
  cache.brandConfig.some(function(rule) {
    return (rule.keywords || []).some(function(keyword) {
      const kw = String(keyword).toLowerCase();
      // 仅纯拉丁数字关键词参与域名比对（中文词不会出现在域名里）
      if (kw.length < 3 || !/^[a-z0-9]+$/.test(kw)) return false;
      if (brandDomainKeywordHit(kw, hostname, registrable)) {
        hitBrand = rule.name; return true;
      }
      // 编辑距离路径：拼写变体比对（仅 ≥6 字符长词，碰撞率低）
      if (kw.length >= 6 && registrable &&
          Math.abs(registrable.length - kw.length) <= 1 &&
          levenshteinWithin1(registrable, kw)) { hitBrand = rule.name; return true; }
      return false;
    });
  });
  return hitBrand;
}

// v2.7.0：沙箱防追踪探测已抽取至 modules/sandbox-probe.js（顶部解构引入
// sandboxProbeUrl；探测缓存/并发去重/8s 超时随模块自持）

// v2.3.4：AI 外链仿冒嫌疑的 ICP 备案裁决——品牌关键词命中只是弱证据
//（todeskai.com 这类"含品牌词但真实运营"的域名很常见），不能直接定可疑。
// 用既有 queryIcpRecord 查注册域备案：有有效备案 → 主体真实存在，嫌疑解除；
// 查无备案 → 仿冒坐实；API 不可用 → 保守回落 warn。
// 同注册域并发去重（多条链接指向同一站点只查一次）；queryIcpRecord 自带
// 当日缓存与失败 5 分钟短缓存，此处仅做 Promise 级去重
const _aiLinkIcpInFlight = new Map();
// v2.3.7：整个裁决的硬超时——实测存在备案接口请求被安全软件（如卡巴斯基）
// 拦截后悬而不决的场景，两个源串行各 8 秒也可能叠到 16 秒以上，
// 徽标会一直停在"ICP核验中"。15 秒无结论按"核验超时"强制回落 warn
const AI_LINK_ICP_TIMEOUT_MS = 15000;
function verifyIcpForAiLink(registrable, hostname, susTag, httpStatus, finalHost) {
  let p = _aiLinkIcpInFlight.get(registrable);
  if (!p) {
    p = queryIcpRecord(registrable).catch(function() { return { queried: false }; });
    _aiLinkIcpInFlight.set(registrable, p);
    p.then(function() { _aiLinkIcpInFlight.delete(registrable); }, function() { /* */ });
  }
  const judged = p.then(function(icpInfo) {
    if (icpInfo && icpInfo.queried && icpInfo.hasIcp) {
      return { level: 'unknown', host: hostname, probed: true,
        reason: susTag + '；但该域名已持有有效 ICP 备案（' +
          (icpInfo.icpNumber || '备案号未知') + '），主体真实存在，仿冒嫌疑解除' };
    }
    if (icpInfo && icpInfo.queried && !icpInfo.hasIcp) {
      return { level: 'warn', host: hostname, probed: true,
        reason: susTag + '；且查无 ICP 备案记录，仿冒嫌疑加重，请勿当作官网访问' };
    }
    const redirectNote = finalHost && finalHost !== hostname
      ? '，重定向至 ' + finalHost : '';
    return { level: 'warn', host: hostname, probed: true,
      reason: susTag + '；ICP 备案核验暂不可用，请谨慎访问（HTTP ' +
        httpStatus + redirectNote + '）' };
  });
  return Promise.race([
    judged,
    new Promise(function(resolve) {
      setTimeout(function() {
        resolve({ level: 'warn', host: hostname, probed: true,
          reason: susTag + '；ICP 备案核验超时（接口无响应，可能被安全软件拦截），请谨慎访问' });
      }, AI_LINK_ICP_TIMEOUT_MS);
    })
  ]);
}

async function classifyAiChatLink(url) {
  const cached = getCachedAiLinkVerdict(url);
  if (cached) return cached;
  let parsed;
  try { parsed = new URL(url); } catch(e) {
    return { level: 'unknown', reason: '无法解析的地址', probed: false };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { level: 'unknown', reason: '非网页协议', probed: false };
  }
  const hostname = parsed.hostname.toLowerCase();
  await refreshWhitelistCache();
  // 白名单/政府域直接定 safe（与 scorePage 同一套豁免口径）
  const whitelisted = setMatches(cloudWhitelistSet, hostname) ||
    isDefaultWhitelisted(hostname) || matchesLocalWhitelist(url) ||
    isRecentlyBypassed(url) || isGovCn(hostname);
  if (whitelisted) {
    return cacheAiLinkVerdict(url, { level: 'safe', host: hostname, probed: false,
      reason: '官方或可信域名（白名单命中）' });
  }
  // 已知恶意：直接定级，不向恶意基础设施发起任何请求
  if (isHardcodedHost(hostname)) {
    return cacheAiLinkVerdict(url, { level: 'danger', host: hostname, probed: false,
      reason: '已知银狐投毒域名（内置库）' });
  }
  if (setMatches(blocklistSet, hostname)) {
    return cacheAiLinkVerdict(url, { level: 'danger', host: hostname, probed: false,
      reason: '恶意域名黑名单命中' });
  }
  // v2.3.2：多信号可疑判定 + http 明文链接；均未命中才落灰不查。
  // v2.3.3：域名品牌词仿冒（含编辑距离变体）同样纳入探测触发，
  // 且置于原因首位——这是对话场景里最高危的钓鱼形态（假官网引导下载）
  const susReasons = aiLinkSuspicionReasons(hostname);
  const impersonatedBrand = aiLinkBrandImpersonation(hostname);
  if (impersonatedBrand) susReasons.unshift('疑似仿冒「' + impersonatedBrand + '」官网域名');
  if (parsed.protocol === 'http:') susReasons.push('HTTP 明文链接');
  if (!susReasons.length) {
    return cacheAiLinkVerdict(url, { level: 'unknown', host: hostname, probed: false,
      reason: '未发现已知风险（未发起访问）' });
  }
  const susTag = susReasons[0] +
    (susReasons.length > 1 ? ' 等 ' + susReasons.length + ' 项可疑特征' : '');
  // 可疑形态：沙箱防追踪探测，重点核对重定向落地点
  const probe = await sandboxProbeUrl(url);
  if (!probe.ok) {
    return cacheAiLinkVerdict(url, { level: 'warn', host: hostname, probed: true,
      reason: susTag + '；沙箱探测失败（' + probe.error + '），请谨慎访问' });
  }
  let finalHost = '';
  try { finalHost = new URL(probe.finalUrl).hostname.toLowerCase(); } catch(e) { /* */ }
  if (finalHost && (isHardcodedHost(finalHost) || setMatches(blocklistSet, finalHost))) {
    return cacheAiLinkVerdict(url, { level: 'danger', host: hostname, probed: true,
      reason: susTag + '，且重定向至恶意域名：' + finalHost });
  }
  // v2.3.4：疑似仿冒不直接定可疑——转入第二阶段 ICP 备案核验裁决。
  // 返回两段式结果：{ interim, final } 由 handleAiChatLinkScan 先回执
  // 过渡态（content 显示 ICP 核验中动画）、再把终局结论推回标签页；
  // 其余路径仍返回单一终局 verdict
  if (impersonatedBrand) {
    const registrable = getRegistrableDomain(hostname) || hostname;
    return {
      interim: { level: 'pendingIcp', host: hostname, probed: true,
        reason: susTag + '；正在核验 ICP 备案…' },
      final: verifyIcpForAiLink(registrable, hostname, susTag,
        probe.status, finalHost)
    };
  }
  // v2.6.0 形态可疑但实测干净的降档：高滥用 TLD/连字符/IP/punycode 等
  // 静态形态信号只是弱证据——实测可正常访问且最终落地回原注册域的站点
  // 并未呈现任何恶意行为，一律按橙色"可疑"展示是外链误报观感的主要来源。
  //   同注册域落地 + HTTP 正常     → unknown（绿点），面板保留完整核查依据；
  //   HTTP ≥400（站点无正常页面）  → unknown，当前无法构成内容危害；
  //   跨注册域重定向（短链中转等）→ 维持 warn（落点不明需警惕）。
  // 注意：疑似仿冒品牌域名不走此降档，仍强制进入 ICP 备案第二阶段裁决
  const homeRegistrable = getRegistrableDomain(hostname) || hostname;
  const finalRegistrable = finalHost ? (getRegistrableDomain(finalHost) || finalHost) : '';
  const probeHttpOk = probe.status >= 200 && probe.status < 400;
  // 落点未知（极少见的解析失败）且 HTTP 正常时按无跳转证据处理——
  // 维持橙色需要"确认跨注册域跳转"，而非"未确认同站"
  if (probeHttpOk && (finalRegistrable === homeRegistrable || !finalRegistrable)) {
    return cacheAiLinkVerdict(url, { level: 'unknown', host: hostname, probed: true,
      reason: susTag + '；沙箱核验通过：HTTP ' + probe.status + ' 可正常访问、' +
        '未发生跨站跳转，暂未发现风险（该域名形态在灰色站点中较常见，保持留意）' });
  }
  if (!probeHttpOk) {
    return cacheAiLinkVerdict(url, { level: 'unknown', host: hostname, probed: true,
      reason: susTag + '；目标站点无正常网页响应（HTTP ' + probe.status +
        '），当前无法构成危害；若日后恢复访问请重新留意' });
  }
  return cacheAiLinkVerdict(url, { level: 'warn', host: hostname, probed: true,
    reason: susTag + '；HTTP ' + probe.status + '，且重定向至无关站点 ' +
      finalHost + '（跳转落点不明，请谨慎访问）' });
}

async function handleAiChatLinkScan(urls, tabId) {
  // v2.3.6：先灌回持久化缓存（SW 重启后首次核查时），命中则零网络开销
  await ensureVerdictStoreLoaded();
  const list = (Array.isArray(urls) ? urls : []).slice(0, AI_LINK_BATCH_MAX);
  const results = {};
  for (const url of list) {
    try {
      const outcome = await classifyAiChatLink(url);
      // v2.3.4：两段式结果——interim 为"ICP 核验中"过渡态立即回执；
      // 终局结论完成后缓存并经 tabs.sendMessage 推回标签页实时刷新徽标
      if (outcome && outcome.interim) {
        results[url] = outcome.interim;
        outcome.final.then(function(verdict) {
          cacheAiLinkVerdict(url, verdict);
          if (tabId == null) return;
          try {
            chrome.tabs.sendMessage(tabId,
              { action: 'aiLinkVerdict', url: url, verdict: verdict },
              function() { void chrome.runtime.lastError; });
          } catch(e) { /* */ }
        }).catch(function() {
          // v2.3.7：终局链路任何异常都必须落地结论并推送——
          // 徽标绝不能停在"检测中/ICP核验中"过渡态
          const fb = { level: 'warn', probed: true,
            reason: '核验流程异常（已中止），请谨慎访问该链接' };
          cacheAiLinkVerdict(url, fb);
          if (tabId == null) return;
          try {
            chrome.tabs.sendMessage(tabId,
              { action: 'aiLinkVerdict', url: url, verdict: fb },
              function() { void chrome.runtime.lastError; });
          } catch(e) { /* */ }
        });
      } else {
        results[url] = outcome || { level: 'unknown', reason: '核查异常', probed: false };
      }
    }
    catch(e) { results[url] = { level: 'unknown', reason: '核查异常', probed: false }; }
  }
  return results;
}

// 消息处理中心：popup / warning / content 脚本的请求入口
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
  // v2.3.0：AI 对话页外链核查；v2.4.0 起同时覆盖 UGC 平台
  //（content.js 在可信 AI 对话/UGC 平台顶层框架发送，后台不重复校验来源域）。
  // 静态分级即时返回；可疑模式域名的沙箱探测异步完成后一并回执
  if (msg.action === 'scanAiChatLinks') {
    handleAiChatLinkScan(msg.urls, sender.tab && sender.tab.id).then(function(results) {
      sendResponse({ ok: true, results: results });
    }).catch(function() {
      sendResponse({ ok: false });  // 兜底：防止发送方永久挂起
    });
    return true;
  }
  if (msg.action === 'refreshRules') {
    // 立即回执"已开始"：规则拉取可能耗时较长（多个远程源依次尝试），
    // 不能让消息通道一直挂起等待，否则 popup 的 await 会永久 pending。
    // 刷新完成后通过 rulesUpdated 广播通知 popup 刷新界面
    sendResponse({ ok: true, started: true });
    refreshRules().then(function() {
      try {
        chrome.runtime.sendMessage({ action: 'rulesUpdated' }, function() {
          void chrome.runtime.lastError;
        });
      } catch(e) { /* */ }
    });
    return false; // 已同步回执，无需保持通道
  }
  if (msg.action === 'getStatus') {
    sendResponse({ rules: cache.blocklist.length, blocked: cache.blockedCount, whitelist: cache.whitelist.length, status: cache.status });
    return true;
  }
  // v2.0.0 新增：内容脚本启动时获取品牌库配置（评分引擎的品牌冒充检测用）
  if (msg.action === 'getBrandConfig') {
    if (cache.brandConfig && cache.brandConfig.length > 0) {
      sendResponse({ brands: cache.brandConfig });
    } else {
      // 品牌库尚未就绪（SW 刚唤醒且 storage 无缓存）：现场拉取一次再回执
      refreshBrands().then(function() {
        sendResponse({ brands: cache.brandConfig });
      });
    }
    return true;
  }
  // v2.1.3 r3：页面冻结——content script 软拦截（100~149）后请求
  // 在页面 MAIN world 静音网络/定时器/动态代码 API。content script 的
  // 隔离世界无法触碰页面 JS 对象，必须经 scripting.executeScript 注入。
  // func 序列化后在页面世界执行，内部不得引用外部变量（自包含）。
  // r3 变更：解冻弃用 r2 的 token 恢复通道（就地还原 API 实测不可靠，
  // 页面全局状态已错乱）——解冻 = 窗口期（markUnfrozen）+ 整页刷新，
  // 刷新后 MAIN world 全新，静音自然消失，无需任何恢复入口
  if (msg.action === 'freezePageJS') {
    const freezeTabId = sender.tab && sender.tab.id;
    // 总开关关闭时不冻结（冻结仅是拦截的强化，开关优先级最高）
    if (!cache.enabled || !freezeTabId) {
      sendResponse({ ok: false, reason: 'disabled' });
      return true;
    }
    // 白名单/政府域复检：评分到冻结的间隙用户可能已将该站加入白名单
    refreshWhitelistCache().then(async function() {
      let freezeHostname = '';
      try { freezeHostname = new URL(sender.tab.url || '').hostname.toLowerCase(); } catch(e) { /* */ }
      if (freezeHostname && (setMatches(allAllowedSet, freezeHostname) || isGovCn(freezeHostname))) {
        sendResponse({ ok: false, reason: 'allowed' });
        return;
      }
      try {
        await chrome.scripting.executeScript({
          target: { tabId: freezeTabId },
          world: 'MAIN',
          injectImmediately: true,
          func: function() {
            // 幂等：重复注入（重评多次触发 freezePageJS）直接跳过
            if (window.__yhPageFrozen) return;
            window.__yhPageFrozen = true;
            function mute(owner, key, replacement) {
              try { owner[key] = replacement; } catch(e) { /* 只读属性等：尽力而为，静默跳过 */ }
            }
            // 抛错版：打断调用方的执行流（网络请求/动态代码）
            function frozen() { throw new Error('PageFrozen'); }
            // Promise 版：fetch 风格的 API 用 reject（调用方按 Promise 处理）
            function frozenPromise() { return Promise.reject(new Error('PageFrozen')); }
            // 静默版：定时器/弹窗等（返回值无意义）
            function noop() { return 0; }
            // ---- 网络出口：切断全部外联 ----
            mute(window, 'fetch', frozenPromise);
            mute(XMLHttpRequest.prototype, 'open', frozen);
            mute(window, 'WebSocket', frozen);
            mute(window, 'EventSource', frozen);
            mute(navigator, 'sendBeacon', noop);
            mute(window, 'open', noop);
            // ---- 动态代码执行 ----
            mute(window, 'eval', frozen);
            mute(window, 'Function', frozen);
            // ---- 定时器：停掉轮询/延迟逻辑/动画循环 ----
            mute(window, 'setTimeout', noop);
            mute(window, 'setInterval', noop);
            // ---- 系统弹窗：防钓鱼/恐吓弹窗 ----
            mute(window, 'alert', noop);
            mute(window, 'confirm', noop);
            mute(window, 'prompt', noop);
            // r3：无需解冻入口——解冻 = 整页刷新，MAIN world 随之重置
          }
        });
        debug('freezePageJS 主世界冻结完成 tabId=' + freezeTabId);
        sendResponse({ ok: true });
      } catch(err) {
        // 注入失败（页面不可脚本化/扩展上下文失效）：DOM 层冻结
        //（横幅冻结态+事件拦截+script 暂存）在 content 侧独立生效，仅缺 API 静音
        console.warn(LOG + 'freezePageJS 注入失败 tabId=' + freezeTabId + ': ' + (err && err.message));
        sendResponse({ ok: false, reason: err && err.message });
      }
    });
    return true; // 异步回执
  }
  // v2.1.3 r3 新增：解冻确认——登记窗口期（hostname 级，30 分钟）。
  // content 侧 unfreezePage 确认后调用，回执即整页刷新；刷新后重评
  // 命中窗口期则回执 unfrozen 标记，content 仅注入警示横幅不再冻结
  if (msg.action === 'markUnfrozen') {
    const unfreezeUrl = msg.url || (sender.tab && sender.tab.url) || '';
    markUnfrozen(unfreezeUrl);
    debug('markUnfrozen 解冻窗口期已登记 url=' + unfreezeUrl);
    sendResponse({ ok: true });
    return true;
  }
  // v2.1.3 新增：popup 域名情报查询——弹窗打开时主动查询当前页的
  // 域名年龄（RDAP）与 ICP 备案（uapis.cn），查询期间 popup 显示
  // 加载动画。复用 enhanceScoreAsync 的同一套查询函数与 24h 缓存，
  // 命中缓存秒回、未命中实时查询（异步回执，查询完才 sendResponse）。
  // 此通道仅供 popup 展示明细——拦截增强计分仍由 enhanceScoreAsync
  // 独立执行（新域名 +40/+20、伪造备案 +20，达线升级硬拦截）
  if (msg.action === 'queryDomainIntel' && msg.url) {
    (async function() {
      try {
        let hostname = '';
        try { hostname = new URL(msg.url).hostname.toLowerCase(); } catch(e) { /* */ }
        const domain = getRegistrableDomain(hostname);
        if (!domain) {
          sendResponse({ ok: false, reason: 'invalid_url' });
          return;
        }
        // v2.3.0：可信 AI 对话页不核验 ICP——对话内备案号是 AIGC/UGC 内容
        // 而非页面声明，popup 的"盗用备案"展示惩罚不生效
        const icpClaimed = !!msg.icpClaimed && !isAiChatHostname(domain);
        const ageInfo = await queryDomainAge(domain);
        const icpInfo = icpClaimed ? await queryIcpRecord(domain) : skipIcpQueryResult();
        debug('queryDomainIntel domain=' + domain + ' age=' + ageInfo.creationDays +
          'd icpClaimed=' + icpClaimed + ' icpQueried=' + icpInfo.queried +
          ' icpSkipped=' + !!icpInfo.skipped + ' icpHas=' + icpInfo.hasIcp);
        sendResponse({
          ok: true,
          domain: domain,
          // 域龄：-1 = 全部数据源查询失败（v2.1.4 起含 WHOIS 兜底链）
          creationDays: ageInfo.creationDays,
          // v2.1.4：命中的域龄数据源标识（rdap/whodat/whoisjs），popup 文案标注用
          ageSource: ageInfo.source || '',
          ageUnsupported: !!ageInfo.unsupported,
          // 备案：skipped=页面无合规备案声明未发起查询；queried=false=API 不可用
          icpSkipped: !!icpInfo.skipped,
          icpQueried: icpInfo.queried,
          icpHas: icpInfo.hasIcp,
          icpNumber: icpInfo.icpNumber || ''
        });
      } catch(e) {
        // 查询异常（网络失败等）：失败安全，popup 显示查询失败
        sendResponse({ ok: false, reason: e && e.message });
      }
    })();
    return true; // 异步回执（实时查询可能耗时数秒，保持消息通道开启）
  }
  // v2.0.0 新增：内容脚本评分上报 → 后台品牌核查补分 → 拦截决策
  if (msg.action === 'scorePage') {
    const result0 = msg.result || {};
    const scoreUrl = result0.url || (sender.tab && sender.tab.url) || '';
    refreshWhitelistCache().then(async function() {
      // 后台二次品牌核查：内容脚本品牌配置未就绪漏检时补分
      const result = applyBrandCheck(result0, scoreUrl);
      let scoreHostname = '';
      try { scoreHostname = new URL(scoreUrl).hostname.toLowerCase(); } catch(e) { /* */ }
      // v2.6.0 用户信任记忆：host 在 7 天信任期内 → 固定抵扣弱化残余启发式
      // 噪声并豁免软拦截冻结（下方 unfrozen 判定同步放宽）。决策与增强增强
      // 两路径共用被改写后的 result.total，保证层级判定口径一致；
      // 白名单/黑名单/强特征通道在此之前已独立短路，不受影响
      await ensureUserTrustLoaded();
      const hostTrusted = isUserTrustedActive(scoreHostname);
      if (hostTrusted && Number(result.total) > 0) {
        const trustDiscount = Math.min(USER_TRUST_DISCOUNT, Number(result.total));
        result.total = Number(result.total) - trustDiscount;
        result.details = Array.isArray(result.details) ? result.details.slice() : [];
        result.details.push({ id: 'userTrustDiscount', label: '历史信任记录抵扣',
          points: -trustDiscount, matched: true,
          evidence: '你此前在本站确认过继续访问/解冻（' +
            Math.round(USER_TRUST_TTL_MS / 86400000) + ' 天内有效），综合评分已作抵扣' });
        debug('scorePage 用户信任抵扣 -' + trustDiscount + ' url=' + scoreUrl);
      }
      // 豁免判断：总开关关闭 / 云白名单 / 默认白名单 / 用户白名单 / 临时放行 /
      // 政府域名（v2.1.0 一律不拦截）
      const allowed = !cache.enabled ||
        setMatches(cloudWhitelistSet, scoreHostname) ||
        isDefaultWhitelisted(scoreHostname) ||
        isGovCn(scoreHostname) ||
        matchesLocalWhitelist(scoreUrl) ||
        isRecentlyBypassed(scoreUrl);
      if (allowed) {
        sendResponse({ ok: true, blocked: false });
        return;
      }
      // 拦截条件（v2.1.2 分层改造，误报治理）：
      //   硬拦截：黑名单命中 / 强特征（noahApi/adseo）单项 / 总分 ≥150 且证据类别 ≥2
      //   软拦截：总分 100~149（或 ≥150 但证据集中在单一类别）——不跳页，
      //           回执 warn=true 由 content 注入顶部警示横幅，浏览不中断
      //   放行：总分 <100
      // v2.1.0 修复（保留）：此处只认数据库命中（blocklistSet）——matchesBlockedDomain
      // 还包含 pattern 模式检测，若用它判定，pattern 域名的官方标识豁免分支
      // 永远不会生效：页面放行后评分上报会被当作"黑名单命中"二次拦截
      // （症状：正规站已注入验证卡片，片刻后又被弹拦截页）。
      // pattern 的拦截决策已移交 handleNav/content 的官方标识检测通道
      const legacyHit = setMatches(blocklistSet, scoreHostname);
      let totalScore = Number(result.total) || 0;
      const strongSignal = !!result.strongSignal;
      let categoryCount = Number(result.categories) || 0;
      // v2.2.0：结构性/资源类证据标记——"过度危险"的判定基础。
      // structure=页面结构分发特征，resource=请求恶意资源
      let categoriesList = Array.isArray(result.categoriesList) ? result.categoriesList : [];
      // v2.2.2：异步增强已有终局结论时直接采用——DOM 重评不再按原始分决策，
      // 消除"注入横幅 → 异步回撤"的闪烁；页面刷新后也立即得到最终层级。
      // 注意：仅覆盖分数与类别维度，品牌/官方标识等页面侧字段保持原值
      const priorVerdict = getEnhancedVerdict(scoreUrl);
      if (priorVerdict) {
        totalScore = priorVerdict.total;
        categoryCount = Number(priorVerdict.categories) || categoryCount;
        if (Array.isArray(priorVerdict.categoriesList)) categoriesList = priorVerdict.categoriesList;
        debug('scorePage 采用增强终局结论 total=' + totalScore + ' url=' + scoreUrl);
      }
      const hasHardEvidence = categoriesList.indexOf('structure') !== -1 ||
        categoriesList.indexOf('resource') !== -1;
      // 硬拦截判定：黑名单 / 强特征 / 高分且证据多样。
      // v2.2.0：纯评分达线（≥150 且类别 ≥2）但无结构性分发证据时不再硬拦——
      // 改走"放行 + 低权琥珀卡片"路径（见下方 noKnownMaliciousSource 分支），
      // 只有黑名单命中、noahApi/adseoResource 强特征或存在结构/资源类证据
      // 才允许直接跳警告页
      const hardBlock = legacyHit || strongSignal || (hasHardEvidence &&
        (totalScore >= 150 && categoryCount >= 2));
      if (!hardBlock) {
        // v2.2.0：达硬拦截线但无已知恶意源且无结构性分发证据 → 放行 + 卡片。
        // "已放行浏览——请核对官网后再下载文件或输入密码"
        // （卡片与警示横幅可叠加：横幅承载评分层级，卡片承载放行结论）
        const pureHighScore = !legacyHit && !strongSignal && totalScore >= 150;
        // 软拦截层：100~149（含 ≥150 但单类别堆分）——警示横幅 + 页面冻结。
        // v2.1.3 r3：解冻窗口期内（用户已确认解冻并刷新）只警示不冻结，
        // 回执带 unfrozen 标记，content 侧据此跳过 freezePageIfNeeded
        if (totalScore >= 100) {
          // v2.6.0：解冻窗口期或用户信任期内都只警示不冻结
          const unfrozen = isRecentlyUnfrozen(scoreUrl) || hostTrusted;
          debug('scorePage 软拦截（警示横幅' + (unfrozen ? '，窗口期内不冻结' : '+冻结') +
            '）tabId=' + (sender.tab && sender.tab.id) +
            ' total=' + totalScore + ' categories=' + categoryCount + ' url=' + scoreUrl);
          sendResponse({ ok: true, blocked: false, warn: true, unfrozen: unfrozen,
            card: pureHighScore, effectiveTotal: totalScore });
        } else if (totalScore >= 80) {
          // v2.1.3 低权重提示层：80~99——灰蓝细横幅（信任降级提示，
          // 不冻结不阻断），风险感知前移，误报零干扰
          debug('scorePage 低权重提示（信任降级横幅' + (pureHighScore ? '+卡片' : '') +
            '）tabId=' + (sender.tab && sender.tab.id) +
            ' total=' + totalScore + ' url=' + scoreUrl);
          sendResponse({ ok: true, blocked: false, notice: true, card: pureHighScore,
            effectiveTotal: totalScore });
        } else {
          // v2.2.0：负分抵扣项（下载入口全指向官方域 -30 / 无实际下载功能 -25）
          // 把分数压到阈值以下的品牌仿冒疑似页也补一张"已放行"卡片——
          // 分数虽低但 brandMatch 存在说明仍有冒充嫌疑，保持风险感知。
          // v2.2.3：备案核验一致（终局结论 icpVerified）时解除嫌疑钉定——
          // 号码与域名备案记录相符是强信任证据，-10 分还挂着"已放行提示"
          // 卡片属于误报残留（与 enhanceScoreAsync 对账层同规则，两处同步）
          const brandCardSuppressed = !!(priorVerdict && priorVerdict.icpVerified);
          const hasBrandSuspicion = !brandCardSuppressed && hasBrandSuspicionFlag(result);
          sendResponse({ ok: true, blocked: false,
            card: (totalScore >= 60 || hasBrandSuspicion),
            effectiveTotal: totalScore });
        }
        // v2.1.3 异步增强（参考开源项目 RDAP/ICP API）：有基础风险的页面
        //（≥60 分）在回执后并查域名年龄与备案记录——新注册域名 +40/+20、
        // 页面声明备案但 API 查无 +20，增强后达硬拦截线则升级拦截。
        // 失败安全：数据源不可用不影响本决策
        if (totalScore >= 60 && sender.tab && sender.tab.id) {
          enhanceScoreAsync(sender.tab.id, scoreUrl, result).catch(function(e) {
            debug('enhanceScoreAsync 失败: ' + e.message);
          });
        }
        return;
      }
      // v2.1.0：官方标识豁免（仅纯评分命中；黑名单命中不豁免）——
      // content script 在评分时顺带检测页面官方标识（CONAC 等），
      // 纯启发式评分达阈值但页面带官方机构标识时放行，
      // 回执 exempt 字段让 content 侧注入悬浮验证卡片
      if (!legacyHit && result.officialBadge) {
        debug('scorePage 官方标识豁免 tabId=' + (sender.tab && sender.tab.id) +
          ' total=' + result.total + ' url=' + scoreUrl);
        sendResponse({ ok: true, blocked: true, exempt: 'official', reason: 'score' });
        return;
      }
      if (!sender.tab || !sender.tab.id) {
        sendResponse({ ok: true, blocked: false });
        return;
      }
      const tabId = sender.tab.id;
      // 防抖：5 秒内同 tab 同 URL 不重复重定向
      const reportKey = tabId + ':' + scoreUrl;
      if (redirectingTabs[reportKey] && Date.now() - redirectingTabs[reportKey] < 5000) {
        sendResponse({ ok: true, blocked: true });
        return;
      }
      redirectingTabs[reportKey] = Date.now();
      cache.blockedCount++;
      storageSet({ blockedCount: cache.blockedCount });
      updateBadge();
      // 拦截记录附带评分明细，警告页据此展示"风险评分"面板与正版官网引导；
      // v2.1.0：附带拦截原因——黑名单命中=database（确切度最高），
      // 纯评分达阈值=score（启发式，多项恶意特征同时命中）
      const blockedInfo = {
        url: scoreUrl, fromUrl: scoreUrl,
        reason: legacyHit ? 'database' : 'score',
        score: result, ts: Date.now()
      };
      saveBlockedPageInfo(tabId, blockedInfo);
      const warningUrl = chrome.runtime.getURL('warning.html') + '?tab=' + tabId +
        '&score=1&url=' + encodeURIComponent(scoreUrl) + '&t=' + Date.now();
      try {
        chrome.tabs.update(tabId, { url: warningUrl }, function() {
          void chrome.runtime.lastError;
        });
      } catch(e) { /* */ }
      debug('scorePage 拦截! tabId=' + tabId + ' total=' + result.total + ' url=' + scoreUrl);
      sendResponse({ ok: true, blocked: true });
    }).catch(function() {
      sendResponse({ ok: false }); // 兜底：防止发送方永久挂起
    });
    return true;
  }
  if (msg.action === 'bypass') {
    // "继续访问/加入白名单"：记录临时放行（hostname 级）+
    // 安装 DNR 会话 allow 规则（host 级，两者覆盖范围对齐）
    markBypassed(msg.url);
    installTemporaryAllow(msg.url, msg.tabId || (sender.tab && sender.tab.id))
      .then(function() { sendResponse({ ok: true }); })
      .catch(function() { sendResponse({ ok: false }); });  // 兜底：防止发送方永久挂起
    return true;
  }
  if (msg.action === 'getLastNavigationUrl') {
    // DNR 静态重定向不携带原始地址，warning 页据此恢复被拦截 URL
    const sourceTabId = msg.tabId || (sender.tab && sender.tab.id);
    sendResponse({ url: sourceTabId ? (lastNavigationUrls.get(sourceTabId) || '') : '' });
    return true;
  }
  if (msg.action === 'getBlocklist') {
    debug('onMessage getBlocklist 请求，返回 ' + cache.blocklist.length + ' 个域名');
    sendResponse({ domains: cache.blocklist, cloudWhitelist: cache.cloudWhitelist });
    return true;
  }
  if (msg.action === 'checkPage') {
    // content.js 首屏检测的二次确认（白名单/开关状态以 background 缓存为准）
    const checkUrl = msg.url || '';
    refreshWhitelistCache().then(function() {
      let checkHostname = '';
      try { checkHostname = new URL(checkUrl).hostname.toLowerCase(); } catch(e) { /* */ }
      const allowed = !cache.enabled || setMatches(cloudWhitelistSet, checkHostname) ||
        isDefaultWhitelisted(checkHostname) ||
        isGovCn(checkHostname) ||                 // v2.1.0：政府域名全豁免
        matchesLocalWhitelist(checkUrl) ||
        isRecentlyBypassed(checkUrl);
      // v2.1.0：回执附带 reason（database=黑名单库立即拦 / pattern=模式域名
      // 交由 content script 做官方标识检测后再决定），首屏流程据此分流
      if (allowed || !matchesBlockedDomain(checkHostname, cache.blocklist)) {
        sendResponse({ blocked: false });
      } else {
        sendResponse({
          blocked: true,
          reason: setMatches(blocklistSet, checkHostname) ? 'database' : 'pattern'
        });
      }
    }).catch(function() {
      sendResponse({ blocked: false });  // 兜底：内部异常时不拦截，DNR 层仍兜底
    });
    return true;
  }
  // ===== v2.1.0：官方标识扫描结果上报（pattern 延迟决策通道）=====
  if (msg.action === 'patternAlive') {
    // content script 确认接手 pattern 检测（已收到 checkPage 回执）：
    // 重置总兜底定时器（PATTERN_TOTAL_TIMEOUT）——拦截决策改为等页面
    // 加载完成（onCompleted 后的上报窗口）再做，加载期间不抢跳；
    // 此消息同时证明 content script 存活，重设计时起点
    const senderTabId = sender.tab && sender.tab.id;
    const entry = senderTabId ? pendingPatternTabs.get(senderTabId) : null;
    if (entry && entry.url === msg.url) {
      armPatternTimer(senderTabId, entry.url, PATTERN_TOTAL_TIMEOUT);
      debug('patternAlive 确认接手 tabId=' + senderTabId + ' url=' + msg.url);
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'officialBadgeFound') {
    // content script 在页面 DOM 中检出官方标识（CONAC 等）：
    // 取消挂起的 pattern 拦截定时器，放行页面（卡片由 content 侧注入）
    const senderTabId = sender.tab && sender.tab.id;
    if (senderTabId && pendingPatternTabs.has(senderTabId)) {
      const entry = pendingPatternTabs.get(senderTabId);
      debug('officialBadgeFound 放行 tabId=' + senderTabId + ' url=' + entry.url);
      clearPatternPending(senderTabId);
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'noBadge') {
    // content script 完成扫描（页面加载完毕）且未检出官方标识：
    // 立即执行挂起的 pattern 拦截
    const senderTabId = sender.tab && sender.tab.id;
    const entry = senderTabId ? pendingPatternTabs.get(senderTabId) : null;
    if (entry) {
      const blockedUrl = entry.url;
      clearPatternPending(senderTabId);
      executePatternBlock(senderTabId, blockedUrl);
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'blockPage') {
    // 内容脚本通过自定义事件报告：该页面正在请求恶意地址
    debug('onMessage blockPage url=' + msg.url + ' fromUrl=' + msg.fromUrl);
    const pageUrl = msg.fromUrl || msg.url || '';
    refreshWhitelistCache().then(function() {
      let pageHostname = '';
      try { pageHostname = new URL(pageUrl).hostname.toLowerCase(); } catch(e) { /* */ }
      // v2.1.1 修复：增加总开关检查——禁用扩展后资源拦截通道不得
      // 继续执行重定向（此前仅 handleNav/checkPage/scorePage 检查开关）
      if (!cache.enabled ||
          setMatches(cloudWhitelistSet, pageHostname) ||
          isDefaultWhitelisted(pageHostname) ||
          isGovCn(pageHostname) ||                    // v2.1.0：政府域名全豁免
          matchesLocalWhitelist(pageUrl) ||
          isRecentlyBypassed(pageUrl)) {
        sendResponse({ ok: true, bypassed: true });
        return;
      }
      cache.blockedCount++;
      storageSet({ blockedCount: cache.blockedCount });
      updateBadge();
      if (sender.tab && sender.tab.id) {
        // 警告页展示并操作用户打开的页面，而不是页面引用的恶意资源；
        // v2.1.0：reason=resource（页面正在请求已知恶意地址/下载恶意程序）
        const blockedInfo = {
          url: pageUrl, fromUrl: pageUrl, resourceUrl: msg.url || '',
          reason: 'resource', ts: Date.now()
        };
        saveBlockedPageInfo(sender.tab.id, blockedInfo);
        const wUrl = chrome.runtime.getURL('warning.html') + '?tab=' + sender.tab.id + '&t=' + Date.now();
        try {
          chrome.tabs.update(sender.tab.id, { url: wUrl }, function() {
            void chrome.runtime.lastError;
          });
        } catch(e) { /* */ }
      }
      sendResponse({ ok: true });
    }).catch(function() {
      sendResponse({ ok: false }); // 兜底：防止发送方永久挂起
    });
    return true;
  }
  if (msg.action === 'getBlockedUrl') {
    // warning 页查询被拦截地址与评分明细（v2.0.0 扩展）：
    // 内存 Map 优先；SW 重启导致内存丢失时回退 storage 持久化副本。
    // 读取不删除，由 clearBlockedUrl 在用户操作（加入白名单/继续访问/前往正版）后清理，
    // 过期记录由 keepAlive 定时修剪
    const tabId = msg.tabId ? parseInt(msg.tabId) : 0;
    const info = tabId ? (blockedPageUrls.get(tabId) || null) : null;
    if (info) {
      // v2.1.0：reason 一并返回，警告页据此渲染"拦截原因"卡片；
      // resourceUrl 一并返回（resource 拦截时为页面实际请求的恶意地址，
      // 缺失会导致警告页"拦截原因"卡片无法展示具体请求目标）
      sendResponse({ url: info.url, fromUrl: info.fromUrl, score: info.score, reason: info.reason, resourceUrl: info.resourceUrl });
      return true;
    }
    if (tabId) {
      chrome.storage.local.get('blockedPage_' + tabId).then(function(stored) {
        const s = stored['blockedPage_' + tabId] || {};
        // storage 回退路径同样返回 resourceUrl（与内存路径字段保持一致）
        sendResponse({ url: s.url, fromUrl: s.fromUrl, score: s.score, reason: s.reason, resourceUrl: s.resourceUrl });
      }).catch(function() {
        sendResponse({ url: '', fromUrl: '', score: undefined, reason: undefined });
      });
    } else {
      sendResponse({ url: '', fromUrl: '', score: undefined, reason: undefined });
    }
    return true;
  }
  // v2.0.0 新增：清理指定标签页的拦截记录（警告页用户操作后调用）
  if (msg.action === 'clearBlockedUrl' && msg.tabId) {
    blockedPageUrls.delete(parseInt(msg.tabId));
    try { chrome.storage.local.remove('blockedPage_' + parseInt(msg.tabId)); } catch(e) { /* */ }
    sendResponse({ ok: true });
    return true;
  }
  // 未识别的消息：统一回执，避免发送方 await 永久挂起
  sendResponse({ ok: false, error: 'unknown action' });
});

chrome.runtime.onInstalled.addListener(function(details) {
  debug('onInstalled reason=' + details.reason);
  initOnce();
  if (details.reason === 'install') {
    // 首次安装：打开欢迎页
    chrome.tabs.create({ url: chrome.runtime.getURL('warning.html?welcome=true') });
  }
});
chrome.runtime.onStartup.addListener(function() { debug('onStartup'); initOnce(); });

// SW 被事件唤醒时也执行初始化（MV3 SW 会被随时终止和重启）
debug('顶层调用 init()');
initOnce();
