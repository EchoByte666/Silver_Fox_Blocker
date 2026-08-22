// 银狐拦截系统 - 警告页面
// 注意：禁止使用内联 onclick/onxxx，CSP 会阻止
// v2.0.0 融合新增：主题切换（浅/深色）、风险评分明细面板、
//                  品牌冒充时的"前往正版网站"引导、拦截记录清理

const STORAGE_KEYS = { WHITELIST: 'whitelist', BLOCKED_COUNT: 'blockedCount' };

function $(id) { return document.getElementById(id); }

// ===== 内联 SVG 图标常量（v2.1.0：全面以 SVG 取代 Emoji/字符图标）=====

// 太阳图标：深色主题下显示（点击切回浅色）
const SUN_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
  + ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
  + '<circle cx="12" cy="12" r="4"/>'
  + '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41'
  + 'M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';

// 月亮图标：浅色主题下显示（点击切到深色）
const MOON_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
  + ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
  + '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

// ===== 拦截原因渲染（v2.1.0 新增）=====

// 各原因的展示元数据：图标 / 名称 / 说明 / 确切度级别。
// 确切度分级约定（数据库为确切度最高的拦截依据，其余次之）：
//   database = 命中黑名单数据库（已确认恶意源）        → high（确切度 最高）
//   resource = 页面请求/引用了已知恶意地址（行为检测）   → high（确切度 高）
//   pattern  = 可疑域名特征（连字符域名等启发式规则）    → mid（确切度 中）
//   score    = 页面风险评分达到阈值（多项特征同时命中）  → mid（确切度 中）
// v2.1.0 修正：resource 的实际检测依据是"页面 fetch/XHR 请求了黑名单域名，
// 或引用了银狐木马常用的 51.la 统计脚本"——请求在发出前即被拦截，
// 并无"下载恶意程序"的事实，文案必须与检测依据一致，不得夸大。
// v2.1.2 变更：51.la 单特征拦截已移除（正规统计服务，误报主源），
// resource 拦截现仅由"页面请求黑名单数据库中的域名"触发——置信度更高
const REASON_META = {
  database: {
    name: '命中恶意网站数据库',
    desc: '该域名已被收录进恶意网站数据库，属于已确认的恶意网站',
    cert: 'high', certLabel: '确切度 最高',
    icon: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/></svg>'
  },
  resource: {
    name: '请求恶意资源',
    desc: '该页面尝试向已知恶意地址加载脚本或数据，请求已在发出前被自动拦截',
    cert: 'high', certLabel: '确切度 高',
    icon: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v11"/><path d="M7 10l5 5 5-5"/><path d="M4 21h16"/></svg>'
  },
  pattern: {
    name: '可疑域名特征',
    desc: '该域名符合银狐木马常用的可疑域名特征（如 xxx-yyy.cc / xxx-yyy.com.cn）',
    cert: 'mid', certLabel: '确切度 中',
    icon: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="7"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/><circle cx="12" cy="12" r="1.2"/></svg>'
  },
  score: {
    name: '页面风险评分达到阈值',
    desc: '页面风险评分已达到拦截阈值，多项恶意特征同时命中',
    cert: 'mid', certLabel: '确切度 中',
    icon: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 15a8 8 0 1 1 16 0"/><path d="M12 15l4.2-4.2"/><circle cx="12" cy="15" r="1.3"/></svg>'
  }
};

// 品牌冒充补充条目的图标（copy 形态，示意"仿冒/复制品"）
const BRAND_ICON_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
  + ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
  + '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';

// ===== 安全状态条文案表（v2.1.3：文案准确性修复）=====
// 旧版静态文案"内容未加载/脚本未执行/文件未下载/设备未接触任何内容"
// 仅对 database 成立——DNR 在网络层重定向导航，页面确实从未加载。
// 其余三类拦截的实际保护事实各不相同，文案必须如实对应：
//   resource：页面加载过程中，向恶意地址的子请求在发出前被拦——
//             主页面已加载，但恶意资源未进入设备
//   pattern： 页面加载完成、官方标识检测未通过后的延迟拦截——
//             页面内容已执行，拦截阻止的是后续访问与进一步风险
//   score：   页面加载完成、评分达硬拦截线后的拦截——同 pattern
//（项目既定原则：拦截文案准确反映实际拦截行为，不夸大）
const CHECK_BADGE_SVG = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor"'
  + ' stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
  + '<path d="M20 6L9 17l-5-5"/></svg>';

const SAFE_STATUS_META = {
  database: {
    // 请求层拦截：导航在网络层即被重定向，三项保护全部真实发生
    badges: ['内容未加载', '脚本未执行', '文件未下载'],
    note: '您的设备未接触该网站的任何内容'
  },
  resource: {
    // 加载过程中的请求拦截：主页面已加载，但恶意请求未发出
    badges: ['请求已拦截', '恶意资源未加载', '文件未下载'],
    note: '拦截发生在页面加载过程中，向恶意地址的请求未发出，相关资源未进入您的设备'
  },
  pattern: {
    // 加载后的延迟拦截：内容已执行，只能如实声明"已终止访问"
    badges: ['风险已识别', '访问已终止', '后续加载已阻止'],
    note: '拦截在页面加载后完成，页面内容已执行；已停止访问以避免进一步风险'
  },
  score: {
    // 加载后的评分拦截：同 pattern 的时机，如实声明
    badges: ['多项风险特征命中', '访问已终止', '后续加载已阻止'],
    note: '拦截在页面加载后完成，页面内容已执行；已停止访问以避免进一步风险'
  }
};

// 按拦截原因更新安全状态条徽章与副文案。
// 文案走 createTextNode 防注入；无记录/未知原因时保持 database 语义
//（DNR 静态重定向不携带记录，其规则同样生成自黑名单数据库）
function renderSafeStatus(reason) {
  const badgesEl = $('safeBadges'), noteEl = $('safeNote');
  if (!badgesEl || !noteEl) return;
  const meta = SAFE_STATUS_META[reason] || SAFE_STATUS_META.database;
  badgesEl.replaceChildren();
  meta.badges.forEach(function(text) {
    const badge = document.createElement('span');
    badge.className = 'safe-badge';
    badge.innerHTML = CHECK_BADGE_SVG;                    // 图标（内部常量，安全）
    badge.appendChild(document.createTextNode(text));     // 文案文本节点
    badgesEl.appendChild(badge);
  });
  noteEl.textContent = meta.note;
}

// 构建单个原因条目 DOM：彩色图标 + 名称 + 说明
function buildReasonItem(name, desc, cert, iconSvg) {
  const item = document.createElement('div');
  item.className = 'reason-item';
  const icon = document.createElement('span');
  icon.className = 'reason-icon ' + cert;      // cert 级别决定图标底色（high红/mid琥珀）
  icon.innerHTML = iconSvg;
  const text = document.createElement('div');
  const nameEl = document.createElement('div');
  nameEl.className = 'reason-name';
  nameEl.textContent = name;
  const descEl = document.createElement('div');
  descEl.className = 'reason-desc';
  descEl.textContent = desc;
  text.appendChild(nameEl);
  text.appendChild(descEl);
  item.appendChild(icon);
  item.appendChild(text);
  return item;
}

// 渲染拦截原因卡片：主原因条目 + 确切度徽章；品牌冒充命中时追加补充条目。
// record 为 getBlockedUrl 的返回值；无记录/旧记录（无 reason 字段）时
// 兜底为 database（DNR 静态重定向等场景的规则同样来自黑名单数据库）
function renderReason(record) {
  const certEl = $('reasonCert'), body = $('reasonBody');
  if (!certEl || !body) return;
  const meta = REASON_META[(record && record.reason)] || REASON_META.database;
  // 徽章文案与配色跟随主原因的确切度级别
  certEl.textContent = meta.certLabel;
  certEl.className = 'reason-cert ' + meta.cert;
  body.replaceChildren();                     // 清空旧内容
  // 评分拦截时说明文字附带具体分数（更直观）
  let desc = meta.desc;
  if (record && record.reason === 'score' && record.score &&
      typeof record.score.total !== 'undefined') {
    desc = '页面风险评分已达拦截阈值（' + record.score.total + ' / ' +
      (record.score.threshold || 100) + ' 分），多项恶意特征同时命中';
  }
  // resource 拦截附带被请求的恶意域名（记录里的 resourceUrl）——
  // 让用户知道页面到底向哪个地址发起了请求，判断更有依据
  if (record && record.reason === 'resource' && record.resourceUrl) {
    try {
      const host = new URL(record.resourceUrl).hostname;
      if (host) desc += '（请求目标：' + host + '）';
    } catch(e) { /* resourceUrl 非法则跳过附加信息 */ }
  }
  body.appendChild(buildReasonItem(meta.name, desc, meta.cert, meta.icon));
  // 品牌冒充命中：追加次要条目（虚线分隔），提示仿冒的具体品牌
  if (record && record.score && record.score.brand &&
      /^https?:\/\//.test(record.score.officialUrl || '')) {
    body.appendChild(buildReasonItem(
      '疑似品牌冒充',
      '该网站疑似冒充「' + record.score.brand + '」的官方网站',
      'mid', BRAND_ICON_SVG
    ));
  }
  // v2.1.3：安全状态条（绿色徽章 + 副文案）跟随拦截原因同步渲染——
  // 各原因的拦截时机不同（请求层/加载中/加载后），保护事实不同，
  // 文案如实对应（见 SAFE_STATUS_META 注释）
  renderSafeStatus(record && record.reason);
}

// ===== 主题切换（v2.0.0 新增）=====
// 约定：settings.theme === 'dark' 时应用深色主题，缺省为浅色
//（与 popup.js 保持相同语义，修改需两处同步）
function applyTheme(theme) {
  const isDark = theme === 'dark';
  document.body.classList.toggle('dark', isDark);
  const btn = $('themeToggle');
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
  } catch(e) {
    // 存储异常时仅切换本次视觉态
    applyTheme(document.body.classList.contains('dark') ? 'light' : 'dark');
  }
}

// 把白名单条目规范化为裸域名（小写、去 * 前缀与首尾点），
// 非法条目返回空串。URL 写法自动取 hostname
function normalizeWhitelistDomain(entry) {
  let value = String(entry || '').trim().toLowerCase();
  if (!value) return '';
  try {
    if (/^https?:\/\//.test(value)) value = new URL(value).hostname.toLowerCase();
    else if (value.includes('://')) return '';
  } catch(e) { return ''; }
  value = value.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  return value && value.includes('.') && !/[\s\/?#:@\[\]]/.test(value) ? value : '';
}

// 校验 URL 是否为安全的 http/https 链接（v2.1.1 安全修复）。
// targetUrl 可能来自 URL 参数（url/from）、拦截记录或导航缓存——
// 这些来源都可被构造为 javascript:/data: 等危险协议。若不校验就直接
// 赋给 location.href，"继续访问"会让危险协议在扩展页面上下文执行
//（扩展页面持有 chrome.* API，XSS 后果远重于普通页面）
function isSafeHttpUrl(url) {
  try {
    const u = new URL(String(url));
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch(e) { return false; }
}

// 获取当前标签页 ID（关闭页面/临时放行时需要）。
// v2.1.1 修复（外部审查指出）：删除 tabs.query(active) fallback——
// warning 页处于后台标签/非当前窗口时，query 会拿到用户正在浏览的
// 其他标签页，"关闭页面"按钮将误关用户的页面（后果严重）。
// warning 页是扩展页面，tabs.getCurrent() 可精确返回自身标签且高度
// 可靠；极端情况下返回 null，由调用方回退 window.close() 兜底
async function getCurrentTabId() {
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab && tab.id != null) return tab.id;
  } catch(e) { /* fallthrough */ }
  return null;
}

// 关闭欢迎页所在的标签页：
// 标签页由 onInstalled 打开（非脚本 window.open），window.close() 通常无效，
// 需要通过 tabs API 主动移除；均失败时回退 window.close()——
// v2.1.1：若 window.close() 也未生效（页面仍在运行），把按钮文案改为
// 手动关闭提示，避免用户以为按钮坏了（setTimeout 回调仅在页面
// 未被成功关闭时才会执行）
async function closeWelcomeTab() {
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab && tab.id != null) {
      await chrome.tabs.remove(tab.id);
      return;
    }
  } catch(e) { /* fallthrough */ }
  window.close();
  setTimeout(function() {
    const cb = $('welcomeCloseBtn');
    if (cb && document.body) cb.textContent = '请手动关闭此标签页';
  }, 200);
}

// 把目标地址加入本地白名单（去重 + 规范化后写回）
async function addToWhitelist(url) {
  try {
    const domain = normalizeWhitelistDomain(url);
    if (!domain) return false;
    const r = await chrome.storage.local.get(STORAGE_KEYS.WHITELIST);
    let wl = r[STORAGE_KEYS.WHITELIST] || [];
    wl = wl.map(normalizeWhitelistDomain)
      .filter(function(item, index, items) { return item && items.indexOf(item) === index; });
    if (wl.indexOf(domain) === -1) wl.push(domain);
    await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: wl });
    return true;
  } catch { return false; }
}

// ===== 风险评分渲染（v2.0.0 新增）=====
// 渲染拦截时保存的评分快照：显示面板 + 总分 + 各风险指标明细；
// 当品牌冒充检测命中（score 带 officialUrl）时，同时显示
// "前往正版网站"引导按钮，并把按钮组切换为 2x2 网格
function renderScore(score) {
  if (!score || !Array.isArray(score.details)) return;
  const panel = $('scorePanel'), container = $('scoreDetails');
  if (!panel || !container) return;
  panel.style.display = 'block';                          // 面板默认隐藏，有数据才显示
  const totalEl = $('scoreTotal');
  // v2.1.1 修复：threshold 兜底——旧版本拦截记录可能缺该字段，
  // 直接拼接会显示 "85 / undefined"
  if (totalEl) totalEl.textContent = score.total + ' / ' + (score.threshold || 100);
  container.replaceChildren();                            // 清空旧内容
  score.details.forEach(function(detail) {
    const row = document.createElement('div');
    row.className = 'score-row' + (detail.matched ? ' hit' : '');   // 命中项加亮
    const label = document.createElement('span');
    label.textContent = detail.label + (detail.evidence ? ' · ' + detail.evidence : '');
    const value = document.createElement('span');
    // 正分=风险（红），负分=安全信号（绿），0=未命中
    value.className = 'score-value' + (detail.points > 0 ? ' positive' : (detail.points < 0 ? ' negative' : ''));
    value.textContent = detail.matched ? ((detail.points > 0 ? '+' : '') + detail.points) : '0';
    row.appendChild(label);
    row.appendChild(value);
    container.appendChild(row);
  });
  // 品牌冒充命中：显示正版官网引导按钮（文案带品牌名）
  const officialButton = $('officialSiteBtn');
  if (officialButton && /^https?:\/\//.test(score.officialUrl || '')) {
    officialButton.style.display = 'flex';                // 与 .btn 的 flex 布局一致
    officialButton.textContent = '前往' + (score.brand || '') + '正版网站';
    officialButton.dataset.url = score.officialUrl;
    // 四按钮切换为 2x2 网格，保持等宽整齐
    const group = $('blockBtnGroup');
    if (group) group.classList.add('four');
  }
}

document.addEventListener('DOMContentLoaded', async function() {
  // 版本号与扩展 ID 徽章
  const versionEl = $('extensionVersion');
  if (versionEl) versionEl.textContent = 'v' + chrome.runtime.getManifest().version;
  const idEl = $('extensionId');
  if (idEl) idEl.textContent = chrome.runtime.id;

  // ===== 作者导航菜单（v2.1.0 新增）=====
  // 点击页脚作者名 EchoByte 展开/收起 Bilibili/GitHub 导航列表；
  // 点击菜单外任意位置自动收起（含主题按钮等页面其他区域）
  const authorWrap = document.querySelector('.author-menu-wrap');
  const authorToggle = $('authorToggle');
  if (authorWrap && authorToggle) {
    authorToggle.addEventListener('click', function(e) {
      e.stopPropagation();                    // 防止触发下方的"点击外部收起"监听
      const open = authorWrap.classList.toggle('open');
      authorToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('click', function(e) {
      if (!authorWrap.contains(e.target)) {   // 点击菜单区域之外时收起
        authorWrap.classList.remove('open');
        authorToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // 主题初始化（v2.0.0）：读取持久化偏好，默认浅色
  try {
    const themeData = await chrome.storage.local.get('settings');
    applyTheme(themeData.settings && themeData.settings.theme === 'dark' ? 'dark' : 'light');
  } catch(e) { applyTheme('light'); }
  const themeBtn = $('themeToggle');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  // 解析 URL 参数：welcome=欢迎页 / tab+url+from=拦截信息
  // v2.1.0 修正：删除 virus 参数——导航拦截（仅域名匹配）曾带 virus=1
  // 显示"正在下载病毒"，但并无下载检测依据；病毒下载文案现改为
  // 按拦截记录的 reason=resource 判断（content script 实际检测到
  // 页面请求恶意资源），见下方获取拦截记录处的判断
  const params = new URLSearchParams(window.location.search);
  const isWelcome = params.get('welcome') === 'true';
  const tabId = params.get('tab');
  const blockedUrl = params.get('url');
  let fromUrl = params.get('from') || '';

  // ---- 欢迎页模式 ----
  if (isWelcome) {
    const ws = $('welcomeSection'), bs = $('blockSection'), ft = document.querySelector('.footer');
    if (ws) ws.classList.add('show');
    if (bs) { bs.classList.remove('show'); bs.style.display = 'none'; }
    if (ft) ft.style.display = 'none';
    const cb = $('welcomeCloseBtn');
    if (cb) cb.addEventListener('click', closeWelcomeTab);
    return;
  }

  // ---- 拦截警告模式 ----
  const ws = $('welcomeSection');
  if (ws) ws.style.display = 'none';
  const bs = $('blockSection');
  if (bs) bs.classList.add('show');

  let targetUrl = '';
  let reasonRendered = false;   // v2.1.0：拦截原因是否已随拦截记录渲染

  // 资源拦截会同时传入 url（恶意资源）和 from（用户打开的页面）。
  // 显示、白名单和继续访问始终以用户打开的页面为准。
  if (fromUrl) {
    targetUrl = fromUrl;
  } else if (blockedUrl) {
    targetUrl = blockedUrl;
  }
  // 从后台读取拦截记录（v2.0.0：即使 URL 参数已有地址也必须读取，
  // 因为评分明细与正版官网引导信息只保存在后台的拦截记录中）
  if (tabId) {
    try {
      const r = await chrome.runtime.sendMessage({ action: 'getBlockedUrl', tabId: parseInt(tabId) });
      if (r) {
        fromUrl = r.fromUrl || '';
        targetUrl = fromUrl || r.url || targetUrl;
        renderScore(r.score);       // 渲染评分面板 + 正版网站引导按钮
        renderReason(r);            // 渲染拦截原因卡片（v2.1.0）
        reasonRendered = true;
        // v2.1.0 修正（二次收紧）：resource 的检测依据是"页面 fetch/XHR
        // 请求了黑名单域名"（v2.1.2 起 51.la 单特征已移除）——
        // 请求在发出前即被拦截，并无"下载病毒"的事实，文案不得夸大；
        // 导航拦截（database/pattern）只是域名匹配，保持默认文案
        if (r.reason === 'resource') {
          const dt = $('dangerText');
          if (dt) dt.textContent = '该页面正在加载恶意内容！已自动拦截';
          const ve = $('virusExtra');   // 威胁区红条（flex 布局：图标 + 文字）
          if (ve) ve.style.display = 'flex';
        }
      }
    } catch(e) { /* */ }
  }
  // 无拦截记录（DNR 静态重定向 / SW 重启后记录过期等）：
  // 兜底渲染默认原因 database（DNR 规则同样生成自黑名单数据库）
  if (!reasonRendered) renderReason(null);

  // DNR 静态重定向不携带原始地址，从后台的标签页导航缓存恢复。
  if (!targetUrl && params.get('dnr') === '1') {
    try {
      const currentTabId = await getCurrentTabId();
      const nav = await chrome.runtime.sendMessage({ action: 'getLastNavigationUrl', tabId: currentTabId });
      if (nav && nav.url) targetUrl = nav.url;
    } catch(e) { /* */ }
  }

  const urlEl = $('blockedUrl');
  // v2.1.1 安全修复（外部审查指出）：targetUrl 协议白名单校验——
  // 仅允许 http/https。攻击者可构造 warning.html?url=javascript:...，
  // 若不拦截，"继续访问"会把危险协议赋给 location.href 在扩展页面
  // 上下文执行脚本。校验失败时清空 targetUrl 并禁用跳转类按钮，
  // 让两个依赖 targetUrl 的按钮自然失效（内部均有 if (targetUrl) 守卫）
  if (targetUrl && !isSafeHttpUrl(targetUrl)) {
    targetUrl = '';
    if (urlEl) urlEl.textContent = '无效地址（不支持的协议）';
    const ib = $('ignoreBtn'), wb = $('whitelistBtn');
    if (ib) ib.disabled = true;
    if (wb) wb.disabled = true;
  } else if (urlEl) {
    urlEl.textContent = targetUrl || '未知地址';
  }

  // 关闭页面（推荐操作）
  const closeBtn = $('closePageBtn');
  if (closeBtn) {
    closeBtn.addEventListener('click', async function() {
      try {
        const tabId = await getCurrentTabId();
        if (tabId) await chrome.tabs.remove(tabId);
        else window.close();
      } catch { window.close(); }
    });
  }

  // 前往正版网站（v2.0.0 新增，品牌冒充时的安全引导）：
  // 先清理后台拦截记录（避免返回时误判），再跳转官方域名。
  // v2.1.1：点击立即禁用——async 处理期间快速双击会重复发消息/重复跳转
  const officialButton = $('officialSiteBtn');
  if (officialButton) {
    officialButton.addEventListener('click', async function() {
      if (this.disabled) return;
      this.disabled = true;
      const officialUrl = this.dataset.url;
      if (!/^https?:\/\//.test(officialUrl || '')) { this.disabled = false; return; }
      try {
        await chrome.runtime.sendMessage({ action: 'clearBlockedUrl', tabId: parseInt(tabId) });
      } catch(e) { /* */ }
      window.location.href = officialUrl;
    });
  }

  // 加入白名单并访问（非常不推荐）。
  // v2.1.1：点击立即禁用防重复触发（双击会重复发 bypass 消息）；
  // 写入失败时恢复按钮允许重试
  const wlBtn = $('whitelistBtn');
  if (wlBtn) {
    wlBtn.addEventListener('click', async function() {
      if (this.disabled) return;
      this.disabled = true;
      if (!targetUrl) { this.disabled = false; return; }
      const added = await addToWhitelist(targetUrl);
      if (!added) {
        this.textContent = '加入白名单失败，请重试';
        this.disabled = false;
        return;
      }
      try {
        await chrome.runtime.sendMessage({ action: 'bypass', url: targetUrl, tabId: await getCurrentTabId() });
        // 清理后台拦截记录（v2.0.0：防止重定向后残留的记录干扰后续判断）
        await chrome.runtime.sendMessage({ action: 'clearBlockedUrl', tabId: parseInt(tabId) });
      } catch(e) {}
      this.textContent = '已加入白名单，即将访问';   // v2.1.0：移除 ✓ 字符（图标统一用 SVG）
      setTimeout(function() { window.location.href = targetUrl; }, 800);
    });
  }

  // 继续访问（不推荐）：先通知后台临时放行，避免再次被拦截。
  // v2.1.1：点击立即禁用防重复触发
  const ignoreBtn = $('ignoreBtn');
  if (ignoreBtn) {
    ignoreBtn.addEventListener('click', async function() {
      if (this.disabled) return;
      this.disabled = true;
      if (!targetUrl) { this.disabled = false; return; }
      try {
        await chrome.runtime.sendMessage({ action: 'bypass', url: targetUrl, tabId: await getCurrentTabId() });
        // 清理后台拦截记录（v2.0.0）
        await chrome.runtime.sendMessage({ action: 'clearBlockedUrl', tabId: parseInt(tabId) });
      } catch(e) {}
      window.location.href = targetUrl;
    });
  }
});
