// 银狐拦截系统 - 弹窗交互
// 职责：展示状态/统计、管理白名单、手动刷新规则与测试连接；
// v2.0.0 融合新增：当前页面评分面板、主题切换（浅/深色）、
//                  内置白名单条目隐藏、问题反馈与获取通知入口

// ===== 工具函数 =====
function $(id) { return document.getElementById(id); }
function setText(id, val) { const el = $(id); if (el) el.textContent = val; }

// 远程拉取节流间隔：距上次成功拉取不足该时长则跳过，
// 避免每次打开弹窗都请求全部 7 个规则源
const FETCH_THROTTLE_MS = 10 * 60 * 1000;

// 远程规则源列表（按优先级依次尝试）。
// 注意：background.js 与 offscreen.js 中有相同列表，修改时需三处同步。
// v2.1.1：移除 http://anti-silverfox.wpidc.top 明文源（HTTP 链路可被
// 中间人篡改规则内容；HTTPS 源 + 内置规则兜底已覆盖其作用）
const RULE_SOURCE_URLS = [
  'https://deepformat.top/yh/fake.txt',
  'https://fyh.johnnyblog.top/fake.txt',
  'https://dfcloud.qzz.io/f/MJTE/fake.txt',
  'https://rvit.top/fake.txt',
  'https://cloud.mcnan.top/fake.txt',
  'https://sysbbs.cn/fake.txt'
];

// 内置白名单（v2.0.0 新增）：这些域名是受保护的核心站点，
// 在列表中隐藏且不可删除，防止用户误移除导致保护失效。
// 注意：与 background.js 的 DEFAULT_WHITELIST（*.qq.com 等写法）语义对应，
// background 侧该列表为代码常量、不写入 storage，此处仅负责 UI 隐藏——
// 两处需人工保持同步，修改任一处时同步另一处
const BUILT_IN_WHITELIST = ['qq.com', 'microsoft.com', 'apple.com', 'lestore.lenovo.com'];

// 硬编码高危域名（始终拦截，即使远程规则没包含）。
// 注意：background.js 与 content.js 中有相同列表，修改时需三处同步。
// v2.1.1 新增于 popup：fetchAndSaveRules 直接写 storage 前必须合并它们，
// 否则"测试连接"保存的远程列表会覆盖掉兜底域名（background 的
// storage.onChanged 虽会补合并进内存缓存，但 storage 本体缺失会导致
// 其他直接读 storage 的消费方漏拦）
const HARDCODED_DOMAINS = ['noah-admin.site', 'page-admin.site'];

// 地球图标 SVG 字符串：作为白名单条目前置的网站徽章
// 内联 SVG 属于 DOM 内容，不受 CSP 图片限制
const GLOBE_SVG = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor"'
  + ' stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/>'
  + '<path d="M3 12h18"/><path d="M12 3a14.5 14.5 0 0 1 0 18"/>'
  + '<path d="M12 3a14.5 14.5 0 0 0 0 18"/></svg>';

// ===== 内联 SVG 图标常量（v2.1.0：全面以 SVG 取代 Emoji/字符图标）=====

// 太阳图标：深色主题下显示（点击切回浅色）
const SUN_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"'
  + ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
  + '<circle cx="12" cy="12" r="4"/>'
  + '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41'
  + 'M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';

// 月亮图标：浅色主题下显示（点击切到深色）
const MOON_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"'
  + ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
  + '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

// 关闭（×）图标：白名单条目的删除按钮（取代原 \u00d7 字符）
const CLOSE_SVG = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor"'
  + ' stroke-width="2.2" stroke-linecap="round">'
  + '<path d="M6 6l12 12M18 6L6 18"/></svg>';

// 计算白名单的可见条目（v2.0.0 新增）：
// 过滤掉内置白名单域名，返回 {domain, index, builtIn}，
// index 保留原始数组下标，删除操作按原始索引执行避免错位
function visibleWhitelistEntries(whitelist) {
  return (whitelist || []).map(function(domain, index) {
    var normalized = String(domain || '').trim().toLowerCase().replace(/^\*\./, '');
    try { if (/^https?:\/\//.test(normalized)) normalized = new URL(normalized).hostname.toLowerCase(); }
    catch(e) { /* 保留用户输入的原始形态展示 */ }
    return { domain: domain, index: index, builtIn: BUILT_IN_WHITELIST.includes(normalized) };
  }).filter(function(entry) { return !entry.builtIn; });
}

// ===== 主题切换（v2.0.0 新增）=====
// 约定：settings.theme === 'dark' 时应用深色主题，缺省为浅色
//（保留 1.1.1 浅色精致 UI 作为默认外观）
// 注意：warning.js 中有相同逻辑，修改时需两处同步
function applyTheme(theme) {
  var isDark = theme === 'dark';
  document.body.classList.toggle('dark', isDark);
  var btn = $('themeToggle');
  if (btn) {
    // v2.1.0：深色时显示太阳（点击切回浅色），浅色时显示月亮（点击切到深色）；
    // 图标为内联 SVG（stroke=currentColor 跟随按钮 color 变色）
    btn.innerHTML = isDark ? SUN_SVG : MOON_SVG;
    btn.title = isDark ? '切换浅色主题' : '切换深色主题';
    btn.setAttribute('aria-label', btn.title);
  }
}

// 切换主题并持久化到 settings.theme
async function toggleTheme() {
  try {
    const r = await chrome.storage.local.get('settings');
    const s = r.settings || {};
    s.theme = s.theme === 'dark' ? 'light' : 'dark';
    await chrome.storage.local.set({ settings: s });
    applyTheme(s.theme);
  } catch(e) { /* 存储异常时仅切换本次视觉态 */ applyTheme(document.body.classList.contains('dark') ? 'light' : 'dark'); }
}

// ===== 当前页面评分（v2.0.0 新增）=====

// 渲染评分面板：summary 显示总分，列表逐项展示"标签 · 证据 + 得分"。
// result 为 content.js scorePage() 的返回值：{total, threshold, details[]}，
// 每项 detail：{label, evidence, points, matched}
function renderScore(result) {
  const container = $('scoreList');
  if (!container) return;
  container.replaceChildren();                 // 清空旧内容
  if (!result || !Array.isArray(result.details)) {
    // 无法评分的场景：chrome:// 页、商店页、无 content script 的页面等
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = '当前标签页无法评分';
    container.appendChild(empty);
    setText('popupScoreSummary', '评分明细 · -- / 100');
    return;
  }
  setText('popupScoreSummary', '评分明细 · ' + result.total + ' / ' + (result.threshold || 150));
  result.details.forEach(function(detail) {
    const row = document.createElement('div');
    row.className = 'score-item' + (detail.matched ? ' hit' : '');   // 命中项加亮
    const label = document.createElement('span');
    label.className = 'score-label';
    label.textContent = detail.label + (detail.evidence ? ' · ' + detail.evidence : '');
    const points = document.createElement('span');
    // 正分=风险（红），负分=安全信号（绿），0=未命中
    points.className = 'score-points' + (detail.points > 0 ? ' positive' : (detail.points < 0 ? ' negative' : ''));
    points.textContent = detail.matched ? ((detail.points > 0 ? '+' : '') + detail.points) : '0';
    row.appendChild(label);
    row.appendChild(points);
    container.appendChild(row);
  });
}

// ===== 域名情报（域龄 + ICP 备案）查询与增强渲染 =====
// popup 打开时自动查询当前页域名年龄（v2.1.4 多源：RDAP → WhoDat →
// whoisjs 兜底链）；仅当页面声明了合规备案号时才查 ICP 备案 API，
// 查询期间在评分明细底部显示加载动画。
// 增强分与 background enhanceScoreAsync 同规则计入总分显示：
//   域龄 <30 天 +40 / 30~90 天 +20；页面声明备案但 API 查无 +20

// v2.1.4：域龄数据源标识 → 展示用"查询依据"文案（与实际命中源一致）
function ageSourceText(source) {
  if (source === 'rdap') return 'RDAP 查询';
  if (source === 'whodat' || source === 'whoisjs') return 'WHOIS 查询';
  return '在线查询';
}

// 追加"查询中"动画行（loadCurrentScore 渲染完基础评分后立即调用）
function appendIntelLoading(icpClaimed) {
  const container = $('scoreList');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'intel-loading';
  row.id = 'intelLoading';
  // 旋转环 + 文案（无页面备案声明时不查 ICP，加载文案随之调整）
  row.innerHTML = '<span class="intel-spinner" aria-hidden="true"></span>' +
    '<span>' + (icpClaimed ? '正在查询域名年龄与 ICP 备案…' : '正在查询域名年龄…') + '</span>';
  container.appendChild(row);
}

// 渲染增强结果：intel 为 queryDomainIntel 回执
// { creationDays, ageUnsupported, icpQueried, icpHas, icpNumber, domain }
// baseTotal 为 content.js 基础总分；icpClaimed 为页面是否声明备案号
function renderIntel(intel, baseTotal, threshold, icpClaimed) {
  const container = $('scoreList');
  if (!container) return;
  // 移除加载动画行（若查询失败则替换为失败提示）
  const loading = $('intelLoading');
  if (loading) loading.remove();

  const header = document.createElement('div');
  header.className = 'intel-header';
  header.textContent = '域名情报增强（域龄多源查询 + ICP 备案核验）';
  container.appendChild(header);

  let bonus = 0; // 增强分累计（与 enhanceScoreAsync 规则一致）

  // --- 增强项 1：域名年龄（v2.1.4：文案标注实际命中源）---
  const ageRow = document.createElement('div');
  ageRow.className = 'score-item';
  const ageLabel = document.createElement('span');
  ageLabel.className = 'score-label';
  const agePoints = document.createElement('span');
  agePoints.className = 'score-points';
  const days = intel.creationDays;
  const sourceTag = '（' + ageSourceText(intel.ageSource) + '）';
  if (intel.ageUnsupported) {
    // 预留分支：v2.1.3 起的 unsupported 标记（现仅防御性保留）
    ageLabel.textContent = '域名年龄 · 该顶级域不支持在线查询';
    agePoints.className += ' ';
    agePoints.textContent = '—';
  } else if (days >= 0 && days < 30) {
    bonus += 40;
    ageRow.classList.add('hit');
    ageLabel.textContent = '新注册域名 · 注册仅 ' + days + ' 天' + sourceTag;
    agePoints.classList.add('positive');
    agePoints.textContent = '+40';
  } else if (days >= 30 && days < 90) {
    bonus += 20;
    ageRow.classList.add('hit');
    ageLabel.textContent = '近期注册域名 · 注册 ' + days + ' 天' + sourceTag;
    agePoints.classList.add('positive');
    agePoints.textContent = '+20';
  } else if (days >= 90) {
    // 老域名：安全参考信息，不计分
    ageLabel.textContent = '域名年龄 · 注册 ' + days + ' 天' + sourceTag;
    agePoints.textContent = '0';
  } else {
    // creationDays = -1：全部数据源查询失败
    ageLabel.textContent = '域名年龄 · 查询失败（所有数据源）';
    agePoints.textContent = '—';
  }
  ageRow.appendChild(ageLabel);
  ageRow.appendChild(agePoints);
  container.appendChild(ageRow);

  // --- 增强项 2：ICP 备案核验 ---
  const icpRow = document.createElement('div');
  icpRow.className = 'score-item';
  const icpLabel = document.createElement('span');
  icpLabel.className = 'score-label';
  const icpPoints = document.createElement('span');
  icpPoints.className = 'score-points';
  if (intel.icpSkipped) {
    // 页面未声明合规备案号：未发起 API 查询（非失败）
    icpLabel.textContent = 'ICP 备案 · 页面未声明合规备案号，跳过 API 核验';
    icpPoints.textContent = '—';
  } else if (!intel.icpQueried) {
    // API 不可用：显示为参考信息，不计分（失败安全）
    icpLabel.textContent = 'ICP 备案 · 查询失败（API 不可用）';
    icpPoints.textContent = '—';
  } else if (intel.icpHas) {
    // 已备案：安全参考信息（备案号经"ICP备/证"严格校验）
    icpLabel.textContent = 'ICP 备案 · ' + (intel.icpNumber || '已备案') + '（API 核验）';
    icpPoints.classList.add('negative');
    icpPoints.textContent = '0';
  } else if (icpClaimed) {
    // 页面声明备案但 API 查无 → 盗用他人备案号
    bonus += 20;
    icpRow.classList.add('hit');
    icpLabel.textContent = '备案号与域名不符 · 页面声明备案但 ' + intel.domain + ' 无备案记录（API 核验）';
    icpPoints.classList.add('positive');
    icpPoints.textContent = '+20';
  } else {
    // 页面声明了备案但 API 查无备案记录（已在 icpClaimed 分支计 +20）
    icpLabel.textContent = 'ICP 备案 · 域名无备案记录（API 核验）';
    icpPoints.textContent = '0';
  }
  icpRow.appendChild(icpLabel);
  icpRow.appendChild(icpPoints);
  container.appendChild(icpRow);

  // 增强分计入总分显示（summary 同步更新；>0 时标注增强来源）
  if (bonus > 0) {
    setText('popupScoreSummary', '评分明细 · ' + (baseTotal + bonus) +
      ' / ' + (threshold || 150) + '（含情报增强 +' + bonus + '）');
  }
}

// 查询失败提示（替换加载行动画）
function renderIntelError() {
  const container = $('scoreList');
  if (!container) return;
  const loading = $('intelLoading');
  if (loading) loading.remove();
  const err = document.createElement('div');
  err.className = 'intel-error';
  err.textContent = '域名年龄 / ICP 备案查询失败，本次评分未含增强项';
  container.appendChild(err);
}

// 查询当前活动标签页的评分：
// 1) 若当前页是警告页（warning.html），改用 getBlockedUrl 取拦截时保存的评分快照；
// 2) 普通网页则向 content.js 发 getPageScore 消息实时评分，
//    随后自动发起域名情报查询（加载动画 → 增强项渲染计入总分）；
// 3) 非 http(s) 页面（chrome:// 等）直接显示无法评分
async function loadCurrentScore() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0]) return renderScore(null);
    // 警告页场景：从 URL 参数中取原标签页 id，向后台取拦截记录（含评分明细）。
    // 拦截记录里的评分若来自异步增强，已含增强明细，无需再查
    const warningPrefix = chrome.runtime.getURL('warning.html');
    if ((tabs[0].url || '').startsWith(warningPrefix)) {
      const params = new URL(tabs[0].url).searchParams;
      const blocked = await chrome.runtime.sendMessage({
        action: 'getBlockedUrl', tabId: parseInt(params.get('tab'))
      });
      return renderScore(blocked && blocked.score);
    }
    // 普通网页：仅 http(s) 可评分（content script 只注入普通页面）
    if (!/^https?:/.test(tabs[0].url || '')) return renderScore(null);
    const result = await chrome.tabs.sendMessage(tabs[0].id, { action: 'getPageScore' });
    renderScore(result);
    // v2.1.3：基础评分渲染完，立即发域名情报查询——先显示加载动画，
    // 回执后追加增强项并更新总分（失败安全：查询失败不影响基础评分）
    if (result && Array.isArray(result.details)) {
      appendIntelLoading(!!result.icpClaimed);
      try {
        const intel = await chrome.runtime.sendMessage({
          action: 'queryDomainIntel',
          url: tabs[0].url,
          icpClaimed: !!result.icpClaimed
        });
        if (intel && intel.ok) {
          renderIntel(intel, result.total, result.threshold || 150, !!result.icpClaimed);
        } else {
          renderIntelError();
        }
      } catch(e) {
        renderIntelError();
      }
    }
  } catch(e) {
    // content script 未注入/未响应（如刚安装未刷新的页面）
    renderScore(null);
  }
}

// ===== 数据加载与渲染 =====

// 加载弹窗展示所需的全部数据（storage → UI）
async function loadPopupData() {
  try {
    setText('extVersion', 'v' + chrome.runtime.getManifest().version);
    const r = await chrome.storage.local.get([
      'blocklist','whitelist','blockedCount','settings','lastRefresh','lastRefreshStatus'
    ]);
    const blocklist = r.blocklist || [];
    const whitelist = r.whitelist || [];
    const blockedCount = r.blockedCount || 0;
    const settings = r.settings || {};
    const enabled = settings.enabled !== false;
    const status = r.lastRefreshStatus || 'pending';
    const lastRefresh = r.lastRefresh || 0;

    setText('blockedCount', blockedCount);
    setText('ruleCount', blocklist.length);
    // 白名单计数只统计可见条目（内置白名单已隐藏，v2.0.0）
    setText('whitelistCount', visibleWhitelistEntries(whitelist).length);

    const toggle = $('toggleEnabled');
    if (toggle) toggle.checked = enabled;
    updateStatusUI(enabled);
    updateRuleStatusUI(status, lastRefresh, blocklist.length);
    applyTheme(settings.theme === 'dark' ? 'dark' : 'light');   // 主题（v2.0.0）
    renderWhitelist(whitelist);
    await loadCurrentScore();                                    // 评分（v2.0.0）
  } catch(e) { /* 静默失败：弹窗无错误出口 */ }
}

// 更新防护开关状态指示灯与文案
function updateStatusUI(enabled) {
  const dot = $('statusDot'), txt = $('statusText');
  if (dot) dot.className = 'status-dot ' + (enabled ? 'active' : 'inactive');
  if (txt) txt.textContent = enabled ? '拦截已启用' : '拦截已暂停';
}

// 更新规则状态行（来源 + 数量 + 更新时间）
function updateRuleStatusUI(status, lastRefresh, ruleCount) {
  const rs = $('ruleStatus'), te = $('ruleStatusText');
  if (!rs || !te) return;
  rs.classList.remove('ok', 'error', 'loading');
  if (ruleCount > 0) {
    rs.classList.add('ok');
    const src = (status === 'remote' || status === 'popup') ? '远程' : (status === 'bundled' ? '内置' : '本地');
    te.textContent = src + '规则 ' + ruleCount + ' 条 (' + timeAgo(lastRefresh) + ')';
  } else if (status === 'pending') {
    rs.classList.add('loading');
    te.textContent = '正在获取规则列表...';
  } else {
    rs.classList.add('error');
    te.textContent = '规则获取失败';
  }
}

// 把时间戳转为"x分钟前/x小时前"的友好描述
function timeAgo(ts) {
  if (!ts) return '未知';
  const s = Math.floor((Date.now() - ts) / 1000);
  // v2.1.1：系统时钟偏差导致未来时间戳（s < 0）也归入"刚刚"，
  // 避免出现"-3分钟前"这类异常文案
  if (s < 60) return '刚刚';
  if (s < 3600) return Math.floor(s/60) + '分钟前';
  return Math.floor(s/3600) + '小时前';
}

// 渲染白名单列表：每条 = 图标徽章 + 域名 + 删除按钮。
// v2.0.0：先过滤内置白名单条目（隐藏不可删），删除按钮携带原始索引
function renderWhitelist(whitelist) {
  const c = $('whitelistContainer'), e = $('emptyState');
  if (!c) return;
  // 注意：容器内含静态子元素 emptyState（HTML 中写死的空态提示），
  // 不能用 replaceChildren() 整体清空——那会把 emptyState 一并删掉，
  // 导致空态提示永远无法显示。只按类名精确移除动态生成的条目
  c.querySelectorAll('.whitelist-item').forEach(function(el) { el.remove(); });
  const entries = visibleWhitelistEntries(whitelist);
  if (entries.length === 0) { if (e) e.style.display = 'block'; return; }
  if (e) e.style.display = 'none';
  entries.forEach(function(entry) {
    const item = document.createElement('div');
    item.className = 'whitelist-item';
    // 前置圆形徽章：浅蓝底 + 地球图标，提升条目辨识度
    const badge = document.createElement('span');
    badge.className = 'site-badge';
    badge.innerHTML = GLOBE_SVG;
    const urlEl = document.createElement('span');
    urlEl.className = 'url';
    urlEl.title = entry.domain;
    urlEl.textContent = entry.domain;
    const btn = document.createElement('button');
    btn.className = 'remove-btn';
    btn.dataset.idx = entry.index;              // 原始数组下标，删除不错位
    btn.title = '删除该白名单条目';
    btn.innerHTML = CLOSE_SVG;                  // v2.1.0：× 字符改为 SVG 关闭图标
    item.appendChild(badge);
    item.appendChild(urlEl);
    item.appendChild(btn);
    c.appendChild(item);
    btn.addEventListener('click', function() { removeFromWhitelist(+this.dataset.idx); });
  });
}

// ===== 操作 =====

// 把白名单条目规范化为裸域名（小写、去 * 前缀与首尾点），
// 非法条目返回空串。URL 写法自动取 hostname。
// 注意：与 warning.js 中 normalizeWhitelistDomain 保持相同语义，修改需两处同步
function normalizeWhitelistDomain(entry) {
  let value = String(entry || '').trim().toLowerCase();
  if (!value) return '';
  try {
    // 支持粘贴完整 URL（http/https），自动提取 hostname
    if (/^https?:\/\//.test(value)) value = new URL(value).hostname.toLowerCase();
    else if (value.includes('://')) return '';  // 其他协议（ftp:// 等）视为非法
  } catch(e) { return ''; }
  // 去掉 *. 通配前缀与首尾点，得到裸域名
  value = value.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  // 必须含点号（形如域名），且不含路径/空格等非法字符
  return value && value.includes('.') && !/[\s\/?#:@\[\]]/.test(value) ? value : '';
}

// 手动添加白名单条目：规范化 → 去重 → 写回 storage。
// 写入后 background 的 storage.onChanged 监听器会自动重建匹配 Set
// 并更新 DNR 规则，四层防护（DNR/导航/内容脚本/评分）立即放行该域名。
// 返回 'added' | 'exists' | 'invalid' | 'storage_error' 供调用方差异化提示
//（v2.1.1 修复：原 catch 一律返回 'invalid'，storage 配额/权限异常时
// 用户会看到"无效域名"的误导提示，现单独区分存储失败）
async function addWhitelistEntry(raw) {
  const domain = normalizeWhitelistDomain(raw);
  if (!domain) return 'invalid';
  try {
    const r = await chrome.storage.local.get('whitelist');
    // 全量规范化 + 去重，顺带清洗历史脏数据（与 warning.js addToWhitelist 一致）
    let wl = (r.whitelist || []).map(normalizeWhitelistDomain)
      .filter(function(item, idx, items) { return item && items.indexOf(item) === idx; });
    if (wl.indexOf(domain) !== -1) return 'exists';
    wl.push(domain);
    await chrome.storage.local.set({ whitelist: wl });
    return 'added';
  } catch(e) {
    return 'storage_error';
  }
}

// 处理"添加白名单"交互：校验 → 入库 → 刷新 UI → 按钮文字反馈。
// 反馈通过按钮文案临时变化呈现（与"更新规则"按钮的交互风格一致），
// 1.5 秒后自动恢复，无需额外 DOM 提示元素
async function handleAddWhitelist() {
  const input = $('whitelistInput'), btn = $('addWhitelistBtn');
  if (!input || !btn) return;
  const raw = input.value.trim();
  if (!raw) {
    input.focus();  // 空输入：聚焦提示用户填写，不弹反馈
    return;
  }
  btn.disabled = true;  // 防止连续点击重复提交
  const result = await addWhitelistEntry(raw);
  if (result === 'added') {
    btn.textContent = '已添加';           // v2.1.0：移除 ✓ 字符（图标统一用 SVG）
    input.value = '';           // 成功后清空输入框，便于连续添加
    loadPopupData();            // 刷新白名单列表与统计数字
  } else if (result === 'exists') {
    btn.textContent = '已存在';
  } else if (result === 'storage_error') {
    btn.textContent = '存储失败，请重试';
  } else {
    btn.textContent = '无效域名';
  }
  // 1.5 秒后恢复按钮文案与可点击状态
  setTimeout(function() {
    btn.textContent = '添加';
    btn.disabled = false;
  }, 1500);
}

// 按原始索引删除一条白名单记录（内置条目已过滤，不会出现在可见列表中）
async function removeFromWhitelist(idx) {
  try {
    const r = await chrome.storage.local.get('whitelist');
    const wl = r.whitelist || [];
    if (idx >= 0 && idx < wl.length) { wl.splice(idx,1); await chrome.storage.local.set({whitelist:wl}); loadPopupData(); }
  } catch(e) { /* */ }
}

// 切换防护开关
async function toggleEnabled(checked) {
  try {
    const r = await chrome.storage.local.get('settings');
    const s = r.settings || {};
    s.enabled = checked;
    await chrome.storage.local.set({settings: s});
    updateStatusUI(checked);
  } catch(e) { /* */ }
}

// 清空白名单（需二次确认；仅清空用户白名单，内置保护不受影响）
async function clearWhitelist() {
  if (!confirm('确定要清空所有白名单记录吗？')) return;
  try { await chrome.storage.local.set({whitelist:[]}); loadPopupData(); } catch(e) { /* */ }
}

// 手动刷新规则与品牌库：通知后台重新拉取（refreshRules 同时刷新
// 黑名单、云白名单与品牌库，v2.0.0 起按钮更名为"更新黑名单和品牌库"）。
// 后台立即回执"已开始"，完成后广播 rulesUpdated，弹窗据此结束等待态。
// 注意：不能依赖 sendMessage 的 await 完成刷新——刷新本身耗时较长，
// 需等待广播；另设 30 秒兜底超时，避免网络异常时按钮永久卡在"更新中"
async function requestRefreshRules() {
  const btn = $('refreshRulesBtn');
  if (!btn) return;
  const originalText = '更新黑名单和品牌库';
  btn.textContent = '更新中...';
  btn.disabled = true;

  let timer = null;
  // 等待后台完成刷新的广播（一次性监听器，收到后自行移除）
  const waitDone = new Promise(function(resolve) {
    const listener = function(msg) {
      if (msg.action === 'rulesUpdated') {
        try { chrome.runtime.onMessage.removeListener(listener); } catch(e) {}
        clearTimeout(timer);
        resolve(true);
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    // 兜底超时：后台迟迟未完成广播时也恢复按钮可用
    timer = setTimeout(function() {
      try { chrome.runtime.onMessage.removeListener(listener); } catch(e) {}
      resolve(false);
    }, 30000);
  });

  // 发起刷新请求（后台立即回执，不会挂起）
  try {
    await chrome.runtime.sendMessage({ action: 'refreshRules' });
  } catch(e) { /* 消息发送失败也会由超时兜底 */ }

  const done = await waitDone;
  btn.textContent = done ? '已更新' : '更新超时';
  // 3 秒后恢复按钮原始文案与可点击状态
  setTimeout(function() { btn.textContent = originalText; btn.disabled = false; }, 3000);
}

// 测试连接：由弹窗直接拉取远程规则并保存。
// force=true 时跳过节流（用户手动点击的场景）；
// 自动拉取（打开弹窗）时受 FETCH_THROTTLE_MS 节流约束
async function fetchAndSaveRules(force) {
  // 节流检查：近期已成功拉取过则跳过，避免重复请求
  if (!force) {
    try {
      const st = await chrome.storage.local.get(['lastRefresh', 'lastRefreshStatus']);
      const fresh = st.lastRefresh && (Date.now() - st.lastRefresh < FETCH_THROTTLE_MS);
      const ok = st.lastRefreshStatus === 'remote' || st.lastRefreshStatus === 'popup';
      if (fresh && ok) return;
    } catch(e) { /* 节流判断失败则继续拉取 */ }
  }

  const btn = $('testFetchBtn'), errEl = $('ruleError');
  // v2.1.1：进入时保存原始文案，恢复时不写死——HTML 标签若调整，
  // 按钮文案不会被打回硬编码旧值
  const originalText = btn ? btn.textContent : '';
  if (btn) { btn.textContent = '获取中...'; btn.disabled = true; }
  if (errEl) errEl.style.display = 'none';

  try {
    // 依次尝试各规则源，任一成功即用。
    // v2.1.0 稳定性修复：单源 15 秒超时（AbortController）——
    // 此前 fetch 无超时，服务器挂起（连接建立但迟迟不响应）时
    // await 会永久 pending，按钮卡死在"获取中..."直到弹窗关闭
    let text = null;
    for (let i = 0; i < RULE_SOURCE_URLS.length; i++) {
      const ctrl = new AbortController();
      const timeoutId = setTimeout(function() { ctrl.abort(); }, 15000);
      try {
        const candidate = await fetch(RULE_SOURCE_URLS[i],
          { cache: 'no-store', signal: ctrl.signal });
        if (candidate.ok) {
          // 响应体读取共用同一超时：整个"请求+读取"流程最多 15 秒
          text = await candidate.text();
        }
      } catch(e) {
        // 超时（AbortError）或网络错误：置空并尝试下一个源
        text = null;
      } finally {
        clearTimeout(timeoutId);
      }
      if (text) break;
    }
    if (!text) throw new Error('所有规则源均不可用');
    // 解析规则：逐行小写化，过滤空行/注释行，要求含点号（形如域名）。
    // v2.1.1 修复（外部审查指出）：保存前合并硬编码高危域名——
    // 远程列表可能未包含 noah-admin.site 等兜底域名，直接覆盖写入
    // 会让 storage 本体丢失它们（background 内存缓存虽有 onChanged
    // 补合并，但直接读 storage 的消费方会漏拦）
    const domains = text.split('\n').map(function(l) { return l.trim().toLowerCase(); }).filter(function(l) {
      return l.length > 0 && !l.startsWith('#') && !l.startsWith('//') && l.includes('.');
    });
    for (let hi = 0; hi < HARDCODED_DOMAINS.length; hi++) {
      if (domains.indexOf(HARDCODED_DOMAINS[hi]) === -1) domains.push(HARDCODED_DOMAINS[hi]);
    }
    if (domains.length > 0) {
      await chrome.storage.local.set({ blocklist: domains, lastRefresh: Date.now(), lastRefreshStatus: 'popup' });
      if (errEl) { errEl.textContent = 'OK! ' + domains.length + ' 个域名已保存'; errEl.style.display = 'block'; errEl.style.color = '#10b981'; }
      if (btn) btn.textContent = '成功';
      loadPopupData();
    } else {
      if (errEl) { errEl.textContent = '解析出 0 个域名'; errEl.style.display = 'block'; errEl.style.color = '#f59e0b'; }
      if (btn) btn.textContent = '无数据';
    }
  } catch(e) {
    if (errEl) { errEl.textContent = '获取失败: ' + e.message; errEl.style.display = 'block'; errEl.style.color = '#ef4444'; }
    if (btn) btn.textContent = '失败';
  }
  // 3 秒后恢复按钮文案与可点击状态（恢复为进入时保存的原文案）
  if (btn) setTimeout(function() { btn.textContent = originalText || '测试连接'; btn.disabled = false; }, 3000);
}

// 在新标签页打开外部链接（反馈页/通知群等，v2.0.0）。
// v2.1.1 加固：协议白名单校验（仅 http/https）——当前调用方全是
// 硬编码安全链接，但若未来改为动态内容，此防线可阻止 javascript:
// 等危险协议被注入打开
function openExternal(url) {
  try {
    const u = new URL(url, location.href);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    chrome.tabs.create({ url: u.href });
  } catch(e) { /* */ }
}

// ===== 事件绑定 =====
document.addEventListener('DOMContentLoaded', function() {
  loadPopupData();
  fetchAndSaveRules(false);  // 自动拉取（带节流）

  let el = $('toggleEnabled');
  if (el) el.addEventListener('change', function() { toggleEnabled(this.checked); });
  // 主题切换（v2.0.0）
  el = $('themeToggle');
  if (el) el.addEventListener('click', toggleTheme);
  // 重新评分（v2.0.0）：向当前页 content script 重新查询评分
  el = $('rescoreBtn');
  if (el) el.addEventListener('click', loadCurrentScore);
  // 清空白名单（v2.0.0 起按钮移至白名单卡片标题行）
  el = $('clearWhitelistBtn');
  if (el) el.addEventListener('click', clearWhitelist);
  // 手动添加白名单：按钮点击 + 输入框回车提交两种方式
  el = $('addWhitelistBtn');
  if (el) el.addEventListener('click', handleAddWhitelist);
  const wlInput = $('whitelistInput');
  if (wlInput) {
    // 回车提交：与按钮点击走同一处理逻辑
    wlInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); handleAddWhitelist(); }
    });
  }
  el = $('testFetchBtn');
  if (el) el.addEventListener('click', function() { fetchAndSaveRules(true); });  // 手动点击强制拉取
  // 更新黑名单和品牌库：通知后台重新拉取规则库（同时刷新品牌库）
  el = $('refreshRulesBtn');
  if (el) el.addEventListener('click', requestRefreshRules);
  // 问题反馈 / 获取通知（v2.0.0 新增的外部入口）
  el = $('feedbackBtn');
  if (el) el.addEventListener('click', function() { openExternal('https://deepformat.top/yh/'); });
  el = $('notificationsBtn');
  if (el) el.addEventListener('click', function() { openExternal('https://qm.qq.com/q/JSNIFvlfyy'); });

  // 后台完成规则刷新后自动刷新界面
  chrome.runtime.onMessage.addListener(function(msg) {
    if (msg.action === 'rulesUpdated') loadPopupData();
  });
});
