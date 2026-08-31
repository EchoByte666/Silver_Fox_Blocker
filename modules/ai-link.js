// 银狐拦截系统 - AI 外链核查模块（v2.7.1 自 background.js 抽取）
// 职责：AI 对话/UGC 平台外链五级结论（danger/warn/safe/unknown/pending）——
//       静态信号分级 → 沙箱防追踪探测（modules/sandbox-probe.js）→ 疑似
//       仿冒域名的 ICP 备案第二阶段裁决；结论缓存 30 分钟并持久化到
//       chrome.storage.session（SW 重启不丢、关浏览器即清）
// 依赖注入：init({ debug, refreshWhitelist, isAllowedTarget, isBlockedHost,
//       getBrandConfig, queryIcpRecord })（background.js 注入，模块不持有
//       黑/白名单 Set 与品牌库等可变状态）
// 导出：__YH_AI_LINK__ = { init, handleAiChatLinkScan }
(function(global) {
'use strict';
const CORE = global.__YH_CORE__;
const { sandboxProbeUrl } = global.__YH_SANDBOX__;
const debug = CORE.debug;
const matchesPatternDomain = CORE.matchesPatternDomain;
const brandDomainKeywordHit = CORE.brandDomainKeywordHit;
const levenshteinWithin1 = CORE.levenshteinWithin1;
const getRegistrableDomain = CORE.getRegistrableDomain;
const HARDCODED_DOMAINS = CORE.HARDCODED_DOMAINS;
let Deps = {};
function init(deps) { Deps = deps; }

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
  if (!Array.isArray(Deps.getBrandConfig()) || !Deps.getBrandConfig().length) return null;
  const hostMatchesDomain = function(domain) {
    domain = String(domain).toLowerCase();
    return hostname === domain || hostname.endsWith('.' + domain);
  };
  const onOfficialSite = Deps.getBrandConfig().some(function(rule) {
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
  Deps.getBrandConfig().some(function(rule) {
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
    p = Deps.queryIcpRecord(registrable).catch(function() { return { queried: false }; });
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
    return { level: 'unknown', host: hostname, probed: true,
      reason: susTag + '；ICP 备案核验暂不可用，无法判断安全性（HTTP ' +
        httpStatus + redirectNote + '）' };
  });
  return Promise.race([
    judged,
    new Promise(function(resolve) {
      setTimeout(function() {
        resolve({ level: 'unknown', host: hostname, probed: true,
          reason: susTag + '；ICP 备案核验超时（接口无响应，可能被安全软件拦截），无法判断安全性' });
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
  await Deps.refreshWhitelist();
  // 白名单/政府域直接定 safe（与 scorePage 同一套豁免口径）
  const whitelisted = Deps.isAllowedTarget(url, hostname);
  if (whitelisted) {
    return cacheAiLinkVerdict(url, { level: 'safe', host: hostname, probed: false,
      reason: '官方或可信域名（白名单命中）' });
  }
  // 已知恶意：直接定级，不向恶意基础设施发起任何请求
  if (isHardcodedHost(hostname)) {
    return cacheAiLinkVerdict(url, { level: 'danger', host: hostname, probed: false,
      reason: '已知银狐投毒域名（内置库）' });
  }
  if (Deps.isBlockedHost(hostname)) {
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
  // v2.7.4：探测失败 → unknown（不是可疑）。站点可能只是临时不可达或
  // 被安全软件拦截，不代表危险——把"查不到"标为"可疑"是误报主要来源之一
  const probe = await sandboxProbeUrl(url);
  if (!probe.ok) {
    return cacheAiLinkVerdict(url, { level: 'unknown', host: hostname, probed: true,
      reason: '沙箱探测失败（' + probe.error + '），无法判断安全性' });
  }
  let finalHost = '';
  try { finalHost = new URL(probe.finalUrl).hostname.toLowerCase(); } catch(e) { /* */ }
  if (finalHost && (isHardcodedHost(finalHost) || Deps.isBlockedHost(finalHost))) {
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
          // v2.3.7：终局链路任何异常都必须落地结论并推送——
          // 徽标绝不能停在"检测中/ICP核验中"过渡态
          const fb = { level: 'unknown', probed: true,
            reason: '核验流程异常（已中止），无法判断安全性' };
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


global.__YH_AI_LINK__ = global.__YH_AI_LINK__ || Object.freeze({
  init: init,
  handleAiChatLinkScan: handleAiChatLinkScan
});
})(globalThis);
