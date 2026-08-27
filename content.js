// 银狐拦截系统 v2.0.0（融合版）- 内容脚本
// 职责：
//   1) document_start 立即检测并重定向恶意页面（在页面渲染前）
//   2) 接收后台 MAIN world 拦截器事件并请求跳转
//   3) 同步黑名单到 localStorage 供后续快速检测
//   4) 页面评分引擎（v2.0.0 新增）：对页面做 30 项风险指标评分，
//      结果上报后台，由后台结合品牌核查与黑名单做拦截决策
//
// 说明：黑名单命中页面在第 1 阶段即被重定向（高置信度直接拦截），
//       评分引擎主要捕捉"不在黑名单里"的仿冒站/变种站

// ===== v2.7.0 模块化：共享配置与纯函数已抽取至 modules/core.js =====
// 由 manifest content_scripts js 数组首位加载（先于本文件，每个 frame 均如此）。
// 单一事实来源——与 background.js 共用同一份副本，修改只改 core.js 一处；
// 本文件顶部解构为顶层绑定，全部调用点零改动
const {
  DEBUG, LOG_PREFIX, debug, HARDCODED_DOMAINS,
  matchesPatternDomain, matchesDomainList, matchesBlockedDomain,
  getRegistrableDomain, isSameSiteHost, isGovCnHostname,
  levenshteinWithin1, isShortLatinKeyword, shortKeywordBoundaryHit,
  brandDomainKeywordHit,
  DEVELOPER_PLATFORM_DOMAINS, SEARCH_ENGINE_DOMAINS,
  isAiChatHostname, isUgcHostname, isSecurityForumHostname
} = globalThis.__YH_CORE__;

// v2.7.0：matchesPatternDomain / matchesDomainList / matchesBlockedDomain /
// getRegistrableDomain / isSameSiteHost / isGovCnHostname 已抽取至
// modules/core.js（顶部解构引入，与 background 共用同一份）

// v2.7.0：getRegistrableDomain / isSameSiteHost / isGovCnHostname 已抽取至
// modules/core.js（顶部解构引入；isGovCnHostname 统一采用含 gov.hk/政务.cn
// 的超集版本，与后台全路径豁免语义对齐）

// v2.7.0：DEVELOPER_PLATFORM_DOMAINS / SEARCH_ENGINE_DOMAINS / AI_CHAT_PLATFORM_DOMAINS /
// UGC_PLATFORM_DOMAINS / SECURITY_FORUM_DOMAINS 及 isAiChatHostname / isUgcHostname /
// isSecurityForumHostname 已抽取至 modules/core.js（顶部解构引入，与 background 共用同一份）

// ===== v2.1.0：官方标识检测（降误报核心）=====
// 检测页面是否挂有"党政机关/事业单位"官方标识——此类标识由机构申请并
// 挂载在页脚（典型形态见 CONAC 全国党政机关事业单位互联网网站标识：
//   <a class="imgs" href="http://bszs.conac.cn/sitename?method=show&id=...">
//     <img src="./static/images/blue.png">
//   </a>）。
// 命中安全规则但带官方标识的页面判定为"疑似官方"，不拦截，
// 改为注入悬浮验证卡片（injectVerifyCard）交由用户自行核实。
//
// v2.1.1 防伪造加固（外部审查指出旧版缺陷：href 只要含 conac.cn 即认可，
// 恶意页面放一个指向 conac.cn 的任意链接就能骗过豁免通道）：
//   - 主通道：严格验证 CONAC 标识链接格式——域名必须是 bszs.conac.cn、
//     路径必须是 /sitename、参数必须为 method=show&id=<32位十六进制>。
//     id 是站点的唯一指纹（形如 53F191ECEBCC1A77E053022819ACC65D），
//     与官方嵌入代码逐字一致才认可，伪造成本大幅提高
//   - 辅助通道：img 资源指向真实 CONAC 域（conac.cn 及其子域，
//     如 szcert.conac.cn）——链接被改写时的图片兜底；
//     alt 文本仅作展示提示、不单独作为判定依据（任意页面都能写 alt）
//   - 协议：http/https 均认可——官方嵌入代码本身即 http，
//     只认 https 会漏检所有按官方文档接入的老站
function isStrictConacLink(href) {
  try {
    const u = new URL(href, location.href);
    if (u.hostname.toLowerCase() !== 'bszs.conac.cn') return false;
    if (u.pathname !== '/sitename') return false;
    if (u.searchParams.get('method') !== 'show') return false;
    const id = u.searchParams.get('id') || '';
    // 32 位十六进制：CONAC 站点指纹的固定长度与字符集
    return /^[0-9A-Fa-f]{32}$/.test(id);
  } catch(e) {
    return false;
  }
}

function detectOfficialBadge() {
  try {
    // 主通道：粗筛 href 属性含 "conac.cn" 的链接（选择器级过滤，
    // 无 CONAC 链接的页面直接跳过 URL 解析开销），再逐个严格验证格式
    const links = document.querySelectorAll('a[href*="conac.cn"]');
    for (let i = 0; i < links.length; i++) {
      if (isStrictConacLink(links[i].href)) return true;
    }
    // 辅助通道：src 含 "conac" 的图片，解析其真实域名是否为 CONAC 域
    // （防止页面随意放一个 alt 含"党政机关"的普通图片即通过检测）
    const imgs = document.querySelectorAll('img[src*="conac"]');
    for (let j = 0; j < imgs.length; j++) {
      try {
        const u = new URL(imgs[j].src, location.href);
        const h = u.hostname.toLowerCase();
        if (h === 'conac.cn' || h.endsWith('.conac.cn')) return true;
      } catch(e) { /* 非法 src：跳过该图片 */ }
    }
  } catch(e) { /* */ }
  return false;
}

// v2.1.0：DOM 就绪回调——readyState 已过 loading 立即执行，否则等 DOMContentLoaded
function onDomReadyThen(fn) {
  if (document.readyState !== 'loading') fn();
  else document.addEventListener('DOMContentLoaded', fn, { once: true });
}

// v2.1.0：页面完全加载回调（等 window load，含图片/样式等全部子资源）——
// readyState 已是 complete 立即执行，否则等 load 事件。
// pattern 拦截的最终决策点：官方标识多在页脚且可能随图片/脚本
// 晚于 DOMContentLoaded 插入，等加载完再扫最稳；加载期间页面保持
// 可见可交互，不会出现"看一半被跳走"的突兀感
function onWindowLoaded(fn) {
  if (document.readyState === 'complete') fn();
  else window.addEventListener('load', fn, { once: true });
}

// ===== v2.1.0：悬浮验证卡片注入 =====
// 触发安全规则但因官方标识被豁免的页面，在右下角注入提示卡片：
// 告知触发的规则 + 指出页面存在官方标识 + 提供官方验证渠道按钮。
// 使用 closed Shadow DOM 隔离页面样式（页面 CSS 无法污染卡片，反之亦然）；
// 仅顶级框架注入（iframe 中不弹卡片）；重复调用幂等（已存在即跳过）
var VERIFY_REASON_TEXT = {
  pattern: '可疑域名特征（连字符域名模式）',
  score: '页面风险评分达到阈值'
};

// 卡片注入状态（闭包变量）：比 DOM id 查询更可靠的幂等标记——
// 恶意页面无法通过预先伪造 __yh_verify_host 元素抢占注入位
var verifyCardInjected = false;

function injectVerifyCard(reason) {
  // 幂等：卡片已注入（或页面即将卸载）则跳过
  if (verifyCardInjected) return;
  // 防伪造/防误注入（纵深防御）：
  // 1) 仅顶级框架注入——iframe 中的卡片会被宿主页裁剪遮挡且语义混乱，
  //    恶意 iframe 也无法借卡片文案伪装"已通过安全核验"
  // 2) 幂等标记用闭包变量而非 DOM id，页面无法伪造占位元素阻断注入
  if (window.top !== window) {
    debug('content.js 拒绝注入验证卡片：非顶级框架');
    return;
  }
  var reasonText = VERIFY_REASON_TEXT[reason] || '安全规则';
  verifyCardInjected = true;

  // 宿主元素：fixed 定位由宿主承担，内部结构走 Shadow DOM
  var host = document.createElement('div');
  host.id = '__yh_verify_host';
  if (!document.body) return;               // body 未就绪（理论不会，等 DOM 后才调用）
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'closed' });

  // 卡片结构：头部（警示图标 + 标题 + 关闭）→ 规则徽章 → 说明 → 验证按钮组。
  // 全部图标使用内联 SVG（与扩展其他页面一致，不依赖外部资源/字体）
  root.innerHTML =
    '<style>' +
    // 宿主定位：fixed 右下角，最高层级确保悬浮可见
    ':host { position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;' +
    '  font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
    // 卡片主体：白底毛玻璃 + 描边 + 投影，与警告页视觉语言一致
    '.card { width: 320px; box-sizing: border-box; background: rgba(255,255,255,0.97);' +
    '  border: 1px solid #e2e8f0; border-radius: 14px; padding: 14px 16px 12px;' +
    '  box-shadow: 0 12px 40px rgba(2,6,23,0.18), 0 2px 8px rgba(2,6,23,0.06);' +
    '  animation: rise .3s ease both; }' +
    '@keyframes rise { from { opacity: 0; transform: translateY(12px); }' +
    '  to { opacity: 1; transform: none; } }' +
    // 头部行：图标 + 标题 + 关闭按钮
    '.head { display: flex; align-items: center; gap: 8px; }' +
    '.head svg { flex-shrink: 0; color: #d97706; }' +
    '.title { font-size: 13.5px; font-weight: 700; color: #1e293b; flex: 1; }' +
    '.close { border: none; background: none; cursor: pointer; padding: 2px;' +
    '  display: flex; color: #94a3b8; border-radius: 6px; }' +
    '.close:hover { color: #475569; background: #f1f5f9; }' +
    // 触发规则徽章（琥珀系：警示但非红色高危）
    '.rule { display: inline-block; margin-top: 8px; font-size: 11px; font-weight: 700;' +
    '  color: #b45309; background: #fef3c7; padding: 2.5px 9px; border-radius: 20px; }' +
    // 说明文字
    '.desc { font-size: 12px; color: #64748b; line-height: 1.65; margin: 8px 0 10px; }' +
    // 验证按钮组：竖排全宽 outline 按钮
    '.links { display: flex; flex-direction: column; gap: 6px; }' +
    '.links a { display: flex; align-items: center; gap: 7px; text-decoration: none;' +
    '  font-size: 12.5px; font-weight: 600; color: #1d4ed8;' +
    '  border: 1px solid #dbeafe; background: #f8faff; border-radius: 8px; padding: 7px 10px; }' +
    '.links a:hover { background: #eff6ff; border-color: #bfdbfe; }' +
    '.links a svg { flex-shrink: 0; opacity: .75; }' +
    // 主操作按钮（v2.1.1）：仅本次访问——收起提示继续浏览，不写入任何存储。
    // 视觉权重最高（蓝色描边），引导用户优先选择低风险动作
    '.main-btn { display: flex; align-items: center; justify-content: center; gap: 7px;' +
    '  width: 100%; box-sizing: border-box; margin-top: 10px; cursor: pointer;' +
    '  font-size: 12.5px; font-weight: 700; color: #1d4ed8; background: #eff6ff;' +
    '  border: 1px solid #bfdbfe; border-radius: 8px; padding: 8px 10px;' +
    '  transition: background .15s, border-color .15s; }' +
    '.main-btn:hover { background: #dbeafe; border-color: #93c5fd; }' +
    // 永久信任按钮（v2.1.1 降权改造）：默认灰底弱化并标注"不推荐"——
    // 永久豁免是高风险动作，不得作为主要确认项引导用户点击；
    // 两段式确认：首次点击进入琥珀警示态（.arm），5 秒内再点才生效
    '.wl-btn { display: flex; align-items: center; justify-content: center; gap: 7px;' +
    '  width: 100%; box-sizing: border-box; margin-top: 6px; cursor: pointer;' +
    '  font-size: 12px; font-weight: 600; color: #64748b; background: #f8fafc;' +
    '  border: 1px solid #e2e8f0; border-radius: 8px; padding: 7px 10px;' +
    '  transition: background .15s, color .15s, border-color .15s; }' +
    '.wl-btn:hover { background: #f1f5f9; color: #475569; }' +
    '.wl-btn.arm { color: #b45309; background: #fef3c7; border-color: #fcd34d; font-weight: 700; }' +
    '.wl-btn:disabled { cursor: default; opacity: .75; }' +
    '.wl-btn.done { color: #059669; background: #ecfdf5; border-color: #a7f3d0; }' +
    '.wl-btn.fail { color: #b91c1c; background: #fef2f2; border-color: #fecaca; }' +
    '</style>' +
    '<div class="card">' +
    '  <div class="head">' +
    // 盾牌问号图标（琥珀）：提示"需自行验证"
    '    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
    '    <span class="title">该页面触发了安全规则</span>' +
    '    <button class="close" title="关闭提示" aria-label="关闭提示">' +
    '      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
    '    </button>' +
    '  </div>' +
    '  <span class="rule">触发规则：' + reasonText + '</span>' +
    // v2.1.1：文案降低信任级别——标识可被仿冒，仅"临时放行"而非"确认官方"
    '  <div class="desc">该页面挂有党政机关/事业单位网站标识（CONAC），' +
    '    已临时放行。标识存在被仿冒的可能，请务必通过下方官方渠道核验后，' +
    '    再进行登录、下载等敏感操作。</div>' +
    '  <div class="links">' +
    // 三个官方验证渠道（新标签打开，noopener 防反向劫持）。
    // v2.1.1：CONAC 链接改用 HTTPS（原 http 明文链路可被 MITM 篡改，
    // 验证页被劫持会误导用户的核验结论）
    '    <a href="https://bszs.conac.cn" target="_blank" rel="noopener noreferrer">' +
    '      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21V7l7-4 7 4v14"/><path d="M9 21v-6h6v6"/></svg>' +
    '      党政机关事业单位标识查询（CONAC）</a>' +
    '    <a href="https://beian.miit.gov.cn" target="_blank" rel="noopener noreferrer">' +
    '      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.5V17a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-5.5"/><path d="M12 15V3"/><path d="M7 10l5 5 5-5"/></svg>' +
    '      工信部 ICP 备案查询</a>' +
    '    <a href="https://beian.mps.gov.cn" target="_blank" rel="noopener noreferrer">' +
    '      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2.5 12h19M12 2.5a15 15 0 0 1 0 19 15 15 0 0 1 0-19z"/></svg>' +
    '      公安备案信息查询</a>' +
    '  </div>' +
    // 主操作（v2.1.1）：仅本次访问——收起卡片继续浏览，不写入任何持久化
    // 存储，本次浏览结束后不残留任何豁免状态（时钟图标：临时性语义）
    '  <button class="main-btn" type="button">' +
    '    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>' +
    '    <span>仅本次访问，关闭提示</span>' +
    '  </button>' +
    // 次操作（v2.1.1 降权）：永久信任——默认弱化呈现并标注"不推荐"，
    // 点击后需在 5 秒内二次确认才写入白名单（防误点永久豁免恶意站）
    '  <button class="wl-btn" type="button">' +
    '    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>' +
    '    <span>永久信任该站点（不推荐）</span>' +
    '  </button>' +
    '</div>';

  // 关闭按钮：移除整个宿主元素
  var closeBtn = root.querySelector('.close');
  if (closeBtn) closeBtn.addEventListener('click', function() { host.remove(); });

  // 主按钮（v2.1.1）："仅本次访问"——直接收起卡片继续浏览。
  // 页面本就处于放行状态，此按钮承担"知情后继续"的语义，
  // 且不写入任何持久化存储，本次浏览结束后不残留豁免状态
  var mainBtn = root.querySelector('.main-btn');
  if (mainBtn) mainBtn.addEventListener('click', function() { host.remove(); });

  // 永久信任按钮（v2.1.1 两段式确认）：
  // 首次点击仅进入警示态（按钮变琥珀、文案要求再次确认），不执行任何写入；
  // 5 秒内再次点击才真正加入白名单——防止用户未核实标识真伪就误点
  // 永久豁免一个实为恶意的站点（外部审查指出的高风险交互）。
  // 确认后走与 popup/警告页完全相同的协议：规范化当前域名 →
  // 去重合并写入 storage.local 的 whitelist 键；background 的
  // storage.onChanged 监听器会自动同步内存缓存、更新 DNR allow
  // 规则并广播内容脚本，无需额外消息
  var wlBtn = root.querySelector('.wl-btn');
  var WL_DEFAULT_TEXT = '永久信任该站点（不推荐）';
  if (wlBtn) wlBtn.addEventListener('click', function() {
    var label = wlBtn.querySelector('span');
    // ---- 第一段：武装确认态（不执行写入） ----
    if (!wlBtn.dataset.armed) {
      wlBtn.dataset.armed = '1';
      if (label) label.textContent = '再次点击确认永久信任';
      wlBtn.classList.add('arm');
      // 5 秒内未二次点击则恢复初始弱化状态
      setTimeout(function() {
        if (wlBtn.dataset.armed && !wlBtn.disabled) {
          delete wlBtn.dataset.armed;
          if (label) label.textContent = WL_DEFAULT_TEXT;
          wlBtn.classList.remove('arm');
        }
      }, 5000);
      return;
    }
    // ---- 第二段：执行加入白名单 ----
    var domain = String(location.hostname || '').toLowerCase()
      .replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
    if (!domain || !domain.includes('.')) {
      if (label) label.textContent = '域名无效，添加失败';
      wlBtn.classList.remove('arm');
      wlBtn.classList.add('fail');
      wlBtn.disabled = true;
      return;
    }
    try {
      chrome.storage.local.get('whitelist', function(stored) {
        var wl = (stored && stored.whitelist) || [];
        // 已在白名单（理论不会：白名单页不会再触发卡片）则直接视为成功
        if (wl.indexOf(domain) === -1) wl.push(domain);
        chrome.storage.local.set({ whitelist: wl }, function() {
          if (chrome.runtime.lastError) {
            if (label) label.textContent = '加入白名单失败，请重试';
            wlBtn.classList.remove('arm');
            wlBtn.classList.add('fail');
            wlBtn.disabled = true;
            return;
          }
          if (label) label.textContent = '已加入白名单';
          wlBtn.classList.remove('arm');
          wlBtn.classList.add('done');
          wlBtn.disabled = true;
          // 成功后 1.5 秒自动收起卡片（页面本身已在放行状态，无需跳转）
          setTimeout(function() { host.remove(); }, 1500);
          debug('content.js 悬浮卡片白名单添加成功: ' + domain);
        });
      });
    } catch(e) {
      if (label) label.textContent = '加入白名单失败，请重试';
      wlBtn.classList.remove('arm');
      wlBtn.classList.add('fail');
      wlBtn.disabled = true;
    }
  });

  debug('content.js 悬浮验证卡片已注入（原因: ' + reason + '）');
}

// ===== v2.1.2：软拦截警示横幅（误报治理分层策略） =====
// 评分处于软拦截区间（100~149）的页面：不再跳警告页阻断浏览，
// 改为在页面顶部注入黄色警示横幅——用户获得风险提示但浏览不中断。
// 误报场景下代价从"整个站点无法访问"降级为"一条可关闭的提示"；
// 真正的高风险页面仍由硬拦截线（150+ 或强特征）直接跳警告页。
//
// 实现约定与验证卡片一致：
//   - closed Shadow DOM 隔离（页面 CSS 无法污染横幅，反之亦然）
//   - 仅顶级框架注入；幂等（闭包变量标记，页面无法伪造占位元素阻断）
//   - 已注入时仅更新分数/命中项文案（DOM 重评后分数会变化）
//   - 关闭后本次浏览不再出现（不写任何持久化存储，刷新页面自然重置）
var warningBannerInjected = false;
// 已注入横幅的文案更新函数：DOM 重评后 evaluate 再次调用时，
// 不重复注入横幅本体，仅刷新分数与命中项文案
var updateWarningBannerText = null;
// v2.1.3 冻结支持（r2 无模态版）：横幅宿主/影子根引用（事件拦截的
// 放行判断 + 冻结态切换用）、最近评分结果（冻结时横幅已被关闭则重建）、
// 横幅冻结态标记（fillBannerText 据此保住冻结文案不被重评覆盖）
var warnBannerHostEl = null;
var warnBannerRoot = null;
var lastWarnResult = null;
var bannerFrozenState = false;

function injectWarningBanner(result) {
  // 幂等：已注入时仅更新文案（评分/命中项会随 DOM 变化）
  if (warningBannerInjected) {
    if (updateWarningBannerText) updateWarningBannerText(result);
    return;
  }
  if (window.top !== window) {
    debug('content.js 拒绝注入警示横幅：非顶级框架');
    return;
  }
  if (!document.body) return;
  warningBannerInjected = true;
  lastWarnResult = result;
  // v2.1.3：评分从 80~99 升到 100+（重评分数变化）时移除低权重横幅，
  // 避免双层横幅叠加（高级别警示优先，低权重提示让位）
  if (noticeBannerHost) {
    try { noticeBannerHost.remove(); } catch(e) { /* */ }
    noticeBannerHost = null;
    updateNoticeBannerText = null;
  }

  // 宿主元素：fixed 顶部通栏，内部结构走 Shadow DOM
  var host = document.createElement('div');
  host.id = '__yh_warn_banner_host';
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'closed' });
  // v2.1.3 r2：登记模块级引用——冻结事件拦截据此放行横幅内交互，
  // setBannerFrozen 据此切换冻结态（不弹模态窗口，冻结入口常驻横幅）
  warnBannerHostEl = host;
  warnBannerRoot = root;

  // 横幅结构：警示图标 + 主文案（含动态分数 span）+ 命中项摘要 + 关闭按钮。
  // 全部图标使用内联 SVG；琥珀系配色与验证卡片同语言（警示但非红色高危）
  root.innerHTML =
    '<style>' +
    ':host { position: fixed; left: 0; right: 0; top: 0; z-index: 2147483647;' +
    '  font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
    '.banner { display: flex; align-items: center; gap: 10px; box-sizing: border-box;' +
    '  max-width: 960px; margin: 0 auto; padding: 9px 14px;' +
    '  background: rgba(254,243,199,0.97); border: 1px solid #fcd34d; border-top: none;' +
    '  border-radius: 0 0 12px 12px; box-shadow: 0 6px 24px rgba(180,83,9,0.14);' +
    '  animation: drop .25s ease both; }' +
    '@keyframes drop { from { opacity: 0; transform: translateY(-10px); }' +
    '  to { opacity: 1; transform: none; } }' +
    '.banner svg.icon { flex-shrink: 0; color: #b45309; }' +
    '.main { flex: 1; min-width: 0; font-size: 12.5px; font-weight: 700;' +
    '  color: #92400e; line-height: 1.5; }' +
    '.sub { display: block; font-size: 11px; font-weight: 500; color: #b45309;' +
    '  margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }' +
    '.close { border: none; background: none; cursor: pointer; padding: 3px; flex-shrink: 0;' +
    '  display: flex; color: #b45309; border-radius: 6px; }' +
    '.close:hover { color: #78350f; background: rgba(180,83,9,0.1); }' +
    // ===== v2.1.3 r2：冻结态行（默认隐藏，.frozen 时显示）=====
    '.freeze-row { display: none; align-items: center; gap: 8px; margin-top: 7px;' +
    '  flex-wrap: wrap; }' +
    '.banner.frozen .freeze-row { display: flex; }' +
    // 冻结态隐藏关闭按钮：解冻入口必须常驻，用户不能把横幅关没
    '.banner.frozen .close { display: none; }' +
    '.frozen-tag { flex-shrink: 0; font-size: 10px; font-weight: 800; color: #fff;' +
    '  background: #b45309; padding: 2px 8px; border-radius: 99px; letter-spacing: 1px; }' +
    '.freeze-hint { font-size: 10.5px; font-weight: 600; color: #92400e; }' +
    '.unfreeze-btn { flex-shrink: 0; border: none; cursor: pointer; font-family: inherit;' +
    '  font-size: 11px; font-weight: 700; padding: 5px 12px; border-radius: 7px;' +
    '  background: #b45309; color: #fff; transition: background .15s ease; }' +
    '.unfreeze-btn:hover { background: #92400e; }' +
    // 两段式确认态：红色，明确风险自负
    '.unfreeze-btn.confirm { background: #dc2626; }' +
    '.unfreeze-btn.confirm:hover { background: #b91c1c; }' +
    '</style>' +
    '<div class="banner">' +
    // 警告三角图标（琥珀）
    '  <svg class="icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
    '  <div class="main"><span class="score-text"></span>' +
    '    <span class="sub"></span>' +
    // v2.1.3 r2：冻结操作行——"已冻结"标签 + 说明 + 解冻按钮（两段式）
    '    <div class="freeze-row">' +
    '      <span class="frozen-tag">已冻结</span>' +
    '      <span class="freeze-hint">脚本已暂存停用 · 点击无响应 · 可滚动检查</span>' +
    '      <button class="unfreeze-btn" type="button">我已核验，解冻网站</button>' +
    '    </div></div>' +
    '  <button class="close" title="关闭提示" aria-label="关闭提示">' +
    '    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
    '  </button>' +
    '</div>';

  // 动态填充/更新文案：评分与命中项在 DOM 重评后会变化，
  // 保留 DOM 引用供后续 evaluate 复用更新（横幅本体不重复注入）
  function fillBannerText(scoreResult) {
    var scoreEl = root.querySelector('.score-text');
    var subEl = root.querySelector('.sub');
    if (scoreEl) scoreEl.textContent = '银狐拦截系统提示：该页面存在 ' +
      matchedCount(scoreResult) + ' 项可疑特征（风险评分 ' + scoreResult.total + '/150），' +
      '请谨慎下载文件与输入账号密码';
    if (subEl) {
      // v2.1.3 r2：冻结态保住冻结说明文案，不被重评的特征摘要覆盖
      if (bannerFrozenState) {
        subEl.textContent = '页面已冻结：脚本暂存停用 · 链接与按钮无响应 · 可滚动检查内容';
        return;
      }
      var items = matchedItemsOf(scoreResult);
      subEl.textContent = items.length > 0
        ? '主要特征：' + items.slice(0, 3).join('、')
        : '';
    }
  }
  function matchedItemsOf(scoreResult) {
    return (scoreResult.details || []).filter(function(item) {
      return item.matched && item.points > 0;
    }).map(function(item) { return item.label; });
  }
  function matchedCount(scoreResult) {
    return matchedItemsOf(scoreResult).length;
  }
  fillBannerText(result);
  // 登记更新函数：后续 evaluate 复用（横幅已注入时刷新文案）
  updateWarningBannerText = fillBannerText;

  // 关闭按钮：移除宿主元素并作废更新函数（本次浏览不再出现，不写存储）。
  // v2.1.3 r2：冻结态下关闭按钮已被 CSS 隐藏，此处仅普通态可达；
  // 同时清空模块级引用（冻结事件拦截的放行判断随之失效，属预期）
  var closeBtn = root.querySelector('.close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function() {
      updateWarningBannerText = null;
      warnBannerHostEl = null;
      warnBannerRoot = null;
      try { host.remove(); } catch(e) { /* */ }
      debug('content.js 警示横幅已关闭');
    });
  }

  // v2.1.3 r3 解冻按钮（冻结态显示）：两段式确认，防误触——
  // 确认后登记窗口期并整页刷新恢复完整功能，窗口期内不再冻结
  var unfreezeBtn = root.querySelector('.unfreeze-btn');
  if (unfreezeBtn) {
    var confirmPending = false;
    var confirmTimer = null;
    unfreezeBtn.addEventListener('click', function() {
      // 非冻结态（横幅刚重建尚未进入冻结态的间隙）不响应
      if (!bannerFrozenState) return;
      if (!confirmPending) {
        confirmPending = true;
        unfreezeBtn.classList.add('confirm');
        unfreezeBtn.textContent = '再次点击确认解冻（风险自负）';
        confirmTimer = setTimeout(function() {
          confirmPending = false;
          unfreezeBtn.classList.remove('confirm');
          unfreezeBtn.textContent = '我已核验，解冻网站';
        }, 5000);
        return;
      }
      if (confirmTimer) clearTimeout(confirmTimer);
      // 立即禁用按钮 + 提示刷新中（防重复触发；r3 解冻 = 窗口期 + 整页刷新）
      unfreezeBtn.disabled = true;
      unfreezeBtn.textContent = '正在重新加载页面…';
      unfreezePage();
    });
  }
  debug('content.js 警示横幅已注入（评分 ' + result.total + '）');
}

// ===== v2.1.3：低权重提示横幅（评分 80~99 信任降级提示层） =====
// 风险分 ≥80 但 <100 的页面：不足以软拦截（警示+冻结），但已有相当
// 风险特征，注入灰蓝细横幅做低权重提示——用户获得风险感知但无任何
// 干扰（比琥珀警示横幅视觉权重更低：更细、灰蓝配色、无强对比）。
// 与警示横幅的层级关系：
//   - 警示横幅（100+）已注入时不降级显示本横幅（高级别优先）
//   - 评分从 80~99 升到 100+ 时，injectWarningBanner 负责移除本横幅
//   - 关闭后本次浏览不再出现（与警示横幅同策略，不写持久化存储）
var noticeBannerHost = null;
var updateNoticeBannerText = null;

function injectNoticeBanner(result) {
  // 警示横幅（100+ 层级）已存在时不降级显示低权重提示
  if (warningBannerInjected) return;
  // 仅顶级框架注入（iframe 内不重复提示）
  if (window.top !== window) return;
  if (!document.body) return;
  // 幂等：已注入时仅更新文案（重评后分数/命中项会变化）
  if (noticeBannerHost) {
    if (updateNoticeBannerText) updateNoticeBannerText(result);
    return;
  }

  noticeBannerHost = document.createElement('div');
  noticeBannerHost.id = '__yh_notice_banner_host';
  document.body.appendChild(noticeBannerHost);
  var root = noticeBannerHost.attachShadow({ mode: 'closed' });

  // 灰蓝细条：视觉权重刻意低于琥珀警示横幅（信息提示而非警告）
  root.innerHTML =
    '<style>' +
    ':host { position: fixed; left: 0; right: 0; top: 0; z-index: 2147483646;' +
    '  font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
    '.banner { display: flex; align-items: center; gap: 9px; box-sizing: border-box;' +
    '  max-width: 860px; margin: 0 auto; padding: 7px 13px;' +
    '  background: rgba(241, 245, 249, 0.97); border: 1px solid #cbd5e1; border-top: none;' +
    '  border-radius: 0 0 11px 11px; box-shadow: 0 4px 16px rgba(51, 65, 85, 0.10);' +
    '  animation: drop .25s ease both; }' +
    '@keyframes drop { from { opacity: 0; transform: translateY(-8px); }' +
    '  to { opacity: 1; transform: none; } }' +
    '.banner svg.icon { flex-shrink: 0; color: #64748b; }' +
    '.main { flex: 1; min-width: 0; font-size: 12px; font-weight: 600;' +
    '  color: #475569; line-height: 1.45; }' +
    '.sub { display: block; font-size: 10.5px; font-weight: 500; color: #64748b;' +
    '  margin-top: 1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }' +
    '.close { border: none; background: none; cursor: pointer; padding: 3px; flex-shrink: 0;' +
    '  display: flex; color: #64748b; border-radius: 6px; }' +
    '.close:hover { color: #334155; background: rgba(51, 65, 85, 0.1); }' +
    '</style>' +
    '<div class="banner">' +
    // 信息圆圈图标（灰蓝，"提示"语义而非"警告"）
    '  <svg class="icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>' +
    '  <div class="main"><span class="score-text"></span>' +
    '    <span class="sub"></span></div>' +
    '  <button class="close" title="关闭提示" aria-label="关闭提示">' +
    '    <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
    '  </button>' +
    '</div>';

  // 文案填充/更新（重评复用，横幅本体不重复注入）
  function fillNoticeText(scoreResult) {
    var scoreEl = root.querySelector('.score-text');
    var subEl = root.querySelector('.sub');
    var items = (scoreResult.details || []).filter(function(item) {
      return item.matched && item.points > 0;
    }).map(function(item) { return item.label; });
    if (scoreEl) scoreEl.textContent = '银狐拦截系统提示：该页面存在 ' + items.length +
      ' 项可疑特征（风险评分 ' + scoreResult.total + '/150），已降低信任评级';
    if (subEl) {
      subEl.textContent = items.length > 0
        ? '特征：' + items.slice(0, 3).join('、')
        : '';
    }
  }
  fillNoticeText(result);
  updateNoticeBannerText = fillNoticeText;

  // 关闭按钮：移除宿主并作废更新函数（本次浏览不再出现）
  var closeBtn = root.querySelector('.close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function() {
      updateNoticeBannerText = null;
      try { noticeBannerHost.remove(); } catch(e) { /* */ }
      noticeBannerHost = null;
      debug('content.js 低权重提示横幅已关闭');
    });
  }
  debug('content.js 低权重提示横幅已注入（评分 ' + result.total + '）');
}

// ===== v2.2.0：低权琥珀卡片（疑似风险已放行场景） =====
// 触发场景（background 回执 card=true）：
//   1) 总分达硬拦截线但无结构性分发证据——纯话术/纯品牌堆分不再跳警告页，
//      改为放行 + 卡片；
//   2) 疑似品牌仿冒但下载入口全部指向官方域 / 无实际下载功能（负分抵扣放行）
//      ——无论分数落在哪一层都补一张"已放行"卡片。
// 形态：右下角轻量琥珀卡片（Shadow DOM，防页面样式干扰/伪造），可关闭，
// 与警示/低权横幅互不排斥（卡片承载"已放行"结论，横幅承载评分层级）。
var noticeCardInjected = false;
var noticeCardUpdateText = null;

function injectNoticeCard(result) {
  // 幂等：已注入时仅更新文案
  if (noticeCardInjected) {
    if (noticeCardUpdateText) noticeCardUpdateText(result);
    return;
  }
  if (window.top !== window) return;
  if (!document.body) return;
  noticeCardInjected = true;

  var host = document.createElement('div');
  host.id = '__yh_notice_card_host';
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'closed' });
  root.innerHTML =
    '<style>' +
    ':host { position: fixed; right: 16px; bottom: 16px; z-index: 2147483645;' +
    '  font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
    '.card { width: 300px; box-sizing: border-box; padding: 11px 13px;' +
    '  background: rgba(254,243,199,0.97); border: 1px solid #fcd34d;' +
    '  border-radius: 12px; box-shadow: 0 8px 28px rgba(180,83,9,0.18);' +
    '  animation: rise .25s ease both; }' +
    '@keyframes rise { from { opacity: 0; transform: translateY(10px); }' +
    '  to { opacity: 1; transform: none; } }' +
    '.head { display: flex; align-items: center; gap: 7px; }' +
    '.head svg.icon { flex-shrink: 0; color: #b45309; }' +
    '.title { flex: 1; min-width: 0; font-size: 11px; font-weight: 800;' +
    '  letter-spacing: 1px; color: #b45309; }' +
    '.close { border: none; background: none; cursor: pointer; padding: 3px;' +
    '  flex-shrink: 0; display: flex; color: #b45309; border-radius: 6px; }' +
    '.close:hover { color: #78350f; background: rgba(180,83,9,0.1); }' +
    '.main { font-size: 12px; font-weight: 600; color: #92400e;' +
    '  line-height: 1.55; margin-top: 6px; }' +
    '.sub { display: block; font-size: 10.5px; font-weight: 500; color: #b45309;' +
    '  margin-top: 3px; line-height: 1.5; }' +
    '</style>' +
    '<div class="card">' +
    '  <div class="head">' +
    '    <svg class="icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
    '    <span class="title">银狐拦截系统 · 已放行提示</span>' +
    '    <button class="close" title="关闭提示" aria-label="关闭提示">' +
    '      <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
    '    </button>' +
    '  </div>' +
    '  <div class="main"></div>' +
    '  <span class="sub"></span>' +
    '</div>';

  // 文案填充/更新（重评复用，卡片本体不重复注入）
  function fillCardText(scoreResult) {
    var items = ((scoreResult && scoreResult.details) || []).filter(function(item) {
      return item.matched && item.points > 0;
    });
    var mainEl = root.querySelector('.main');
    if (mainEl) {
      mainEl.textContent = '该页面存在 ' + items.length + ' 项可疑特征（风险评分 ' +
        ((scoreResult && scoreResult.total) || 0) + '/150），已放行浏览';
    }
    var subEl = root.querySelector('.sub');
    if (subEl) subEl.textContent = '请核对官网后再下载文件或输入账号密码';
  }
  fillCardText(result);
  noticeCardUpdateText = fillCardText;

  var closeBtn = root.querySelector('.close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function() {
      noticeCardUpdateText = null;
      try { host.remove(); } catch(e) { /* */ }
      debug('content.js 低权琥珀卡片已关闭');
    });
  }
  debug('content.js 低权琥珀卡片已注入（评分 ' + result.total + '）');
}

// ===== v2.2.1 评分回撤 Toast / v2.2.2 扩展为升降级双向 / v2.2.5 改为拦截方式变更提示 =====
// 触发时机（v2.2.5 收窄）：仅当"拦截方式"实际切换时弹出——
//   硬拦截跳页 / 警示横幅(冻结) / 低权横幅 / 提示卡片 / 放行 之间的互切。
// 同一方式内的分数波动、卡片叠加增减一律静默（详见 applyScoreVerdict），
// 另有 15 秒防抖冷却抑制阈值抖动的反复弹。文案以"防护等级变化 + 新的
// 拦截方式"为主语，分数仅作辅助信息——用户需要知道的是"现在页面被怎么处理"。
// 页面顶部居中短暂提示（Shadow DOM 防伪造），6 秒自动消退，可点击立即关闭。
// 方向与文案（direction 由对账层按层级升降判定，仅在方式变更时非空）：
//   down + clear + 曾冻结 → "已下调防护…限制已解除…正在刷新"
//   down + clear          → "已下调防护…解除本页警示与限制"
//   down + 其他           → "已下调防护…降低提示等级"
//   up  + warn            → "已升级防护…警示横幅（并冻结交互）"
//   up  + notice/card     → 对应的新方式说明
function injectScoreChangeToast(info) {
  if (window.top !== window) return;
  if (!document.body) return;
  // 已有 Toast 在显示：移除旧的再注入新的（最新结论优先）
  var staleToast = document.getElementById('__yh_downgrade_toast_host');
  if (staleToast) { try { staleToast.remove(); } catch(e) { /* */ } }

  var host = document.createElement('div');
  host.id = '__yh_downgrade_toast_host';
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'closed' });
  var total = Number(info && info.total) || 0;
  var isUp = !!(info && info.direction === 'up');
  var scoreTag = '（评分 ' + total + '/150）';
  var text;
  if (isUp) {
    if (info.level === 'blocked') {
      text = '本页风险已达硬拦截标准' + scoreTag + '，正在转入拦截页…';
    } else if (info.level === 'warn') {
      text = '防护等级已上调：本页已改为风险警示横幅管控' + scoreTag +
        (info.frozen ? '，并冻结页面交互，请谨慎操作' : '');
    } else if (info.level === 'notice') {
      text = '防护等级已上调：本页已改为低权提示横幅管控' + scoreTag + '，请谨慎操作';
    } else {
      text = '防护等级已上调：本页显示风险提示卡片' + scoreTag +
        '，请核对官网后再下载文件或输入账号密码';
    }
  } else if (info && info.level === 'clear') {
    if (info.wasFrozen) {
      text = '防护等级已下调：本页限制已解除' + scoreTag + '，正在刷新页面…';
    } else {
      text = '防护等级已下调：已解除本页全部警示与限制' + scoreTag + '，可正常浏览';
    }
  } else {
    text = '防护等级已下调：本页提示等级已降低' + scoreTag;
  }
  // 升级=琥珀警示配色；降级=绿色解除配色
  var bg = isUp ? 'rgba(255,251,235,0.97)' : 'rgba(236,253,245,0.97)';
  var borderColor = isUp ? '#f59e0b' : '#34d399';
  var shadowColor = isUp ? 'rgba(180,83,9,0.18)' : 'rgba(5,150,105,0.18)';
  var iconColor = isUp ? '#b45309' : '#059669';
  var textColor = isUp ? '#92400e' : '#065f46';
  var iconSvg = isUp
    ? '<svg class="icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
    : '<svg class="icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
  root.innerHTML =
    '<style>' +
    ':host { position: fixed; top: 14px; left: 50%; transform: translateX(-50%);' +
    '  z-index: 2147483647; font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
    '.toast { display: flex; align-items: center; gap: 8px; max-width: 480px;' +
    '  box-sizing: border-box; padding: 9px 14px;' +
    '  background: ' + bg + '; border: 1px solid ' + borderColor + ';' +
    '  border-radius: 10px; box-shadow: 0 6px 22px ' + shadowColor + ';' +
    '  animation: toast-in .25s ease both, toast-out .4s ease 5.6s both;' +
    '  cursor: pointer; }' +
    '@keyframes toast-in { from { opacity: 0; transform: translateY(-8px); }' +
    '  to { opacity: 1; transform: none; } }' +
    '@keyframes toast-out { to { opacity: 0; transform: translateY(-8px); } }' +
    '.icon { flex-shrink: 0; color: ' + iconColor + '; }' +
    '.text { font-size: 12px; color: ' + textColor + '; line-height: 1.5; }' +
    '</style>' +
    '<div class="toast" role="status">' +
    iconSvg +
    '  <span class="text">银狐拦截系统：' + text + '</span>' +
    '</div>';
  // 点击或动画结束（6s）后整体移除
  var toastEl = root.querySelector('.toast');
  function dismiss() { try { host.remove(); } catch(e) { /* */ } }
  if (toastEl) toastEl.addEventListener('click', dismiss);
  setTimeout(dismiss, 6000);
  debug('content.js 评分变化 Toast 已注入 dir=' + (isUp ? 'up' : 'down') +
    ' level=' + (info && info.level));
}

// ===== v2.2.0 异步增强对账 / v2.2.2 扩展为升降级双向对账 =====
// 同步决策先于增强数据返回：页面可能已按原始分数注入横幅/卡片甚至冻结。
// 后台 enhanceScoreAsync 算出增强结论与同步 UI 层级不一致时发 scoreAdjusted，
// 本处理器把页面 UI 调整到目标层级——升降均伴随 Toast（injectScoreChangeToast）。
//   level='clear'  → 移除全部横幅与卡片；若仍处冻结态则登记窗口期自动解冻刷新
//                     （打断一次浏览——负向证据压倒性时这是恢复功能的唯一途径）
//   level='card'   → 仅保留低权琥珀卡片，移除各级横幅
//   level='notice' → 低权横幅（携带增强后明细），卡片按 msg.card 决定去留
//   level='warn'   → 警示横幅；msg.freeze 且尚未冻结时执行冻结
// v2.2.2 BUG 修复：旧版仅在原始总分 ≥100 时触发回撤，60~99 分的琥珀卡片
// 场景被遗漏（评分 70 弹卡后备案核验一致 -80 → 卡片残留不消失、无提示）

// UI 层级序数（供方向判定；blocked=硬拦截跳页，等级最高）
var UI_LEVEL_RANK = { none: 0, clear: 0, card: 1, notice: 2, warn: 3, blocked: 4 };

// 当前已应用的 UI 状态（同步回执与本处理器共同维护）：
// 用于对账去重（结论与展示一致时不重复弹 Toast）与升级/降级方向判定
var appliedUiState = { level: 'none', card: false, total: null };

function recordAppliedUi(level, card, total) {
  appliedUiState = { level: level, card: !!card, total: Number(total) || 0 };
}

// v2.2.5 防抖冷却：拦截方式在阈值附近来回抖动时（DOM 动态增删特征导致
// 分数反复跨越层级线），15 秒内不重复弹 Toast——UI 照常切换到最新结论，
// 仅提示被抑制。scoreEscalated（升到硬拦截）不受此限制：它是跳转前唯一提示
var SCORE_TOAST_COOLDOWN_MS = 15000;
var lastScoreToastTs = 0;

// 对账消息入口：后台异步增强结论到达时调用（带 Toast）
function handleScoreAdjusted(msg) {
  applyScoreVerdict(msg, true);
}

// v2.2.4：统一裁决应用器——同步回执与异步对账共用同一套层级切换逻辑。
// 此前同步重评路径只注入新层级 UI：不清除旧层级残留（琥珀卡片叠在横幅上）、
// 不弹 Toast，出现"升到 80 无提示""100+ 有冻结无提示"等不对账现象
//   allowToast=true 且拦截方式（UI 层级）确实切换且非首次应用 → 弹 Toast
//     （另受 15 秒防抖冷却约束，见 SCORE_TOAST_COOLDOWN_MS）
//   同方式内分数波动 / 卡片增减 / 首次应用 → 一律静默，仅幂等更新 UI
function applyScoreVerdict(msg, allowToast) {
  var level = msg && Object.prototype.hasOwnProperty.call(UI_LEVEL_RANK, msg.level)
    ? msg.level : 'clear';
  // 归一化：同步路径的"无 UI"记作 none，异步消息记作 clear——序数相同，
  // 统一为 clear 避免去重比较因字符串不同而失效（每次重评误报降级 Toast）
  if (level === 'none') level = 'clear';
  var total = Number(msg && msg.total) || 0;
  var wantCard = !!(msg && msg.card) && level !== 'clear';
  var cur = appliedUiState;
  // 完全一致（层级、卡片标记、总分均相同）→ 不动 UI 不弹 Toast
  if (level === cur.level && wantCard === cur.card && total === cur.total) {
    debug('content.js scoreAdjusted 与当前展示一致，跳过 level=' + level);
    return;
  }
  var curRank = UI_LEVEL_RANK[cur.level] || 0;
  var newRank = UI_LEVEL_RANK[level] || 0;
  var isFirstApply = cur.total === null;
  // v2.2.5：Toast 只跟随"拦截方式"变化——拦截方式 = UI 层级
  // （blocked 硬拦截 / warn 警示横幅 / notice 低权横幅 / card 提示卡片 / clear 放行）。
  //   - 同一方式内的分数波动（85↔95、卡片层 65↔75）：仅静默更新文案，不弹 Toast；
  //     旧版把同层分数变化按 wantCard 判成 up/down，是"分数一变就弹 Toast"的根因
  //   - 卡片叠加标记（wantCard）是展示细节而非拦截方式：增减只静默处理
  //   - 首次应用不算变更（页面初始拦截/放行本就静默）
  var methodChanged = !isFirstApply && newRank !== curRank;
  var direction = methodChanged ? (newRank < curRank ? 'down' : 'up') : '';
  debug('content.js 收到评分对账 ' + cur.level + '→' + level +
    ' total=' + total + (methodChanged ? ' dir=' + direction : '（方式未变，静默）'));

  // 回撤方向的冻结解除：登记窗口期并整页刷新（r3 方案，见 freezePage 注释）。
  // 先记录 wasFrozen 供 Toast 文案区分"解冻刷新"与普通回撤
  var wasFrozen = direction === 'down' && freezeApplied && !pageUnfrozen;
  if (wasFrozen) unfreezePage();

  // 警示横幅：目标不是 warn → 移除
  if (level !== 'warn' && warnBannerHostEl) {
    try { warnBannerHostEl.remove(); } catch(e) { /* */ }
    warnBannerHostEl = null;
    warnBannerRoot = null;
    warningBannerInjected = false;
    updateWarningBannerText = null;
    bannerFrozenState = false;
  }
  // 低权横幅：目标不是 notice → 移除
  if (level !== 'notice' && noticeBannerHost) {
    try { noticeBannerHost.remove(); } catch(e) { /* */ }
    noticeBannerHost = null;
    updateNoticeBannerText = null;
  }
  // 琥珀卡片：按目标决定保留（幂等更新文案）或移除
  if (wantCard) {
    injectNoticeCard({ total: total, details: (msg && msg.details) || [] });
  } else {
    noticeCardUpdateText = null;
    var staleCard = document.getElementById('__yh_notice_card_host');
    if (staleCard) { try { staleCard.remove(); } catch(e) { /* */ } }
    noticeCardInjected = false;
  }
  // 目标为警示层：注入/更新横幅（用增强后的明细渲染）；需要冻结且尚未
  // 冻结时执行冻结（冻结门槛已由后台按 structure/resource 类证据判定）
  if (level === 'warn') {
    var enhancedResult = {
      total: total,
      details: (msg && msg.details) || [],
      categoriesList: (msg && msg.categoriesList) || []
    };
    injectWarningBanner(enhancedResult);
    if (msg && msg.freeze && !freezeApplied && !pageUnfrozen) {
      freezePageIfNeeded(enhancedResult);
    }
  }

  recordAppliedUi(level, wantCard, total);

  // v2.2.5 Toast 触发条件（三者同时满足）：
  //   1) allowToast（同步回执与异步对账均允许，scoreEscalated 直弹不走此处）
  //   2) 拦截方式确实切换（methodChanged）——分数变化/卡片增减一律静默
  //   3) 通过防抖冷却（15 秒内不重复提示，抑制阈值抖动的反复弹）
  if (!allowToast || !methodChanged) return;
  var now = Date.now();
  if (now - lastScoreToastTs < SCORE_TOAST_COOLDOWN_MS) {
    debug('content.js Toast 冷却期内（' +
      Math.ceil((SCORE_TOAST_COOLDOWN_MS - (now - lastScoreToastTs)) / 1000) +
      's 后恢复），仅切换 UI 不提示');
    return;
  }
  lastScoreToastTs = now;

  // 拦截方式变更 Toast：文案以"防护等级升降 + 新的拦截方式"为主语，
  // 让用户明确知道当前页面被以何种方式处理（冻结场景下页面即将刷新，
  // Toast 在刷新前短暂可见；刷新后首次应用静默，不会重复弹出）
  injectScoreChangeToast({
    direction: direction,
    level: level,
    total: total,
    wasFrozen: wasFrozen,
    frozen: freezeApplied && !pageUnfrozen
  });
}

// ===== v2.1.3 r3：页面冻结（评分 100~149 软拦截层强化，无模态 + 窗口期解冻） =====
// 用户要求：保持横幅形态、不弹模态窗口——页面一切照常可见可滚动检查，
// 但所有链接/按钮点击无反应、脚本暂存停用；用户核验后在横幅上解冻。
//
// 版本演进（r1→r2→r3 的解冻方案）：
//   r1（全屏覆盖层）：解冻只移除覆盖层——script 删除与 window.stop()
//      均不可逆，页面功能载体已永久损坏，"解冻无效"
//   r2（token 就地还原）：script 暂存后按原位置还原 + MAIN world API
//      经 token 校验恢复。实测仍不可靠：还原的 script 重新执行时页面
//      全局状态已错乱（重复声明/监听器重复注册/被 reject 的 Promise
//      已走错误分支），功能异常
//   r3（窗口期 + 整页刷新，当前版）：确认解冻后登记窗口期并
//      location.reload()——所有 script/iframe/资源完整重新加载，
//      页面状态全新，功能必然正常。窗口期内（默认 30 分钟，见
//      background 的 markUnfrozen/isRecentlyUnfrozen）同站刷新
//      不再冻结，仅保留警示横幅
//
//   [冻结]（不变）
//     1. window.stop()：停止后续资源加载（冻结检查的是"当下状态"；
//        解冻 = 刷新，天然获得完整加载）
//     2. script/iframe 暂存后移除：阻止未执行脚本（async/延迟/动态
//        挂载的第二阶段载荷）继续运行（r3 无需还原，刷新即重置）
//     3. MutationObserver：冻结期间动态插入的 script/iframe 即插即
//        暂存（不在冻结窗口外泄任何新脚本）
//     4. MAIN world 静音网络/定时器/动态代码 API（经 background
//        executeScript 注入；r3 无需恢复通道，刷新后 MAIN world 全新）
//     5. document 捕获阶段拦截 click/auxclick/submit：链接、按钮、
//        表单全部无响应。刻意不拦键盘/滚轮/右键——保留滚动检查、
//        快捷键与"检查元素"能力（用户要能检查该网站）
//     6. 警示横幅切换冻结态：显示"已冻结"标签与解冻按钮（关闭按钮
//        隐藏——解冻入口必须常驻；横幅此前已被用户关闭则重建）
//   [解冻]（r3：横幅解冻按钮两段式确认后）
//     1. 断开暂存器与事件拦截（刷新前先恢复基本交互，防刷新失败卡死）
//     2. 通知 background 登记窗口期（hostname 级，30 分钟）
//     3. location.reload() 整页刷新 → 全部元素重新加载，功能恢复
//     4. 刷新后重评命中窗口期：回执带 unfrozen 标记，仅注入警示
//        横幅、不再冻结
var freezeApplied = false;       // 已执行冻结（防重复冻结）
var pageUnfrozen = false;        // 用户已解冻（本次浏览永不再冻结）
var freezeObserver = null;       // 冻结期间的 script/iframe 暂存器
var freezeEventBlocker = null;   // 捕获阶段事件拦截函数（解冻时移除）
var stashedNodes = [];           // 暂存的 script/iframe 节点（r3 仅供刷新前清理，不再还原）
// 被拦截的事件类型：链接跳转/按钮点击/中键新开标签/表单提交。
// 刻意不含键盘/滚轮/右键——冻结期间保留页面检查能力
var FREEZE_BLOCKED_EVENTS = ['click', 'auxclick', 'submit'];

// 软拦截回执入口：幂等守卫后执行冻结
function freezePageIfNeeded(result) {
  if (pageUnfrozen || freezeApplied) return;
  // 仅顶级框架冻结（iframe 内页面的交互由顶层捕获拦截统一阻断）
  if (window.top !== window) return;
  if (!document.body) return;
  // v2.2.0 冻结门槛收紧：冻结是误报代价最重的动作（页面瘫痪感）。
  // 仅在总分 ≥100 且命中 structure/resource 类证据时执行——
  // 纯话术/纯品牌堆分到 100+ 的页面只保留警示横幅、不冻结
  var freezeCategories = (result && result.categoriesList) || [];
  var hasHardEvidence = freezeCategories.indexOf('structure') !== -1 ||
    freezeCategories.indexOf('resource') !== -1;
  if (!(Number(result && result.total) >= 100 && hasHardEvidence)) {
    debug('content.js 跳过冻结：无结构性/资源类证据（v2.2.0 门槛收紧）');
    return;
  }
  freezeApplied = true;
  freezePage(result);
}

// 暂存并移除单个 script/iframe 节点：
// 记录父节点与后继兄弟引用，解冻时按原位置精确还原
function stashNode(el) {
  if (!el || el.nodeType !== 1) return;
  try {
    stashedNodes.push({ node: el, parent: el.parentNode, next: el.nextSibling });
    el.remove();
  } catch(e) { /* */ }
}

function freezePage(result) {
  lastWarnResult = result;
  // 1. 停止后续加载（评分时 load 多半未完成；未进入的资源不再加载——
  //    冻结检查的是当下状态，解冻说明里已提示可刷新获得完整加载）
  try { window.stop(); } catch(e) { /* */ }

  // 2. 现存 script/iframe 暂存后移除（可逆冻结核心：移除阻止未执行
  //    脚本运行，暂存引用供解冻还原）
  try {
    var scripts = document.querySelectorAll('script');
    for (var si = 0; si < scripts.length; si++) stashNode(scripts[si]);
    var iframes = document.querySelectorAll('iframe');
    for (var ii = 0; ii < iframes.length; ii++) stashNode(iframes[ii]);
  } catch(e) { /* */ }

  // 3. 冻结期间动态插入的 script/iframe 即插即暂存（银狐站常在页面
  //    稳定后挂载第二阶段载荷；子树内的一并处理）
  freezeObserver = new MutationObserver(function(muts) {
    for (var mi = 0; mi < muts.length; mi++) {
      var added = muts[mi].addedNodes;
      for (var ai = 0; ai < added.length; ai++) {
        var node = added[ai];
        if (!node || node.nodeType !== 1) continue;
        var tag = node.tagName;
        if (tag === 'SCRIPT' || tag === 'IFRAME') {
          stashNode(node);
        } else if (node.querySelectorAll) {
          try {
            var inner = node.querySelectorAll('script, iframe');
            for (var ni = 0; ni < inner.length; ni++) stashNode(inner[ni]);
          } catch(e) { /* */ }
        }
      }
    }
  });
  try { freezeObserver.observe(document.documentElement, { childList: true, subtree: true }); }
  catch(e) { freezeObserver = null; }

  // 4. MAIN world API 静音：background 注入 MAIN world 静音网络/
  //    定时器/动态代码 API（r3 无需 token 恢复通道——解冻 = 整页
  //    刷新，刷新后 MAIN world 全新，静音自然消失）
  try {
    chrome.runtime.sendMessage({ action: 'freezePageJS' }, function() {
      void chrome.runtime.lastError; // 通道异常静默（扩展失效等）
    });
  } catch(e) { /* */ }

  // 5. 捕获阶段事件拦截：链接/按钮/表单点击全部无反应。
  //    横幅（含解冻按钮）的事件经 composedPath 放行——Shadow DOM
  //    事件路径含宿主元素，据此识别自家 UI
  freezeEventBlocker = function(e) {
    if (warnBannerHostEl && e.composedPath &&
        e.composedPath().indexOf(warnBannerHostEl) !== -1) return;
    e.preventDefault();
    e.stopPropagation();
  };
  for (var bi = 0; bi < FREEZE_BLOCKED_EVENTS.length; bi++) {
    document.addEventListener(FREEZE_BLOCKED_EVENTS[bi], freezeEventBlocker, true);
  }

  // 6. 横幅切换冻结态（无模态窗口，解冻入口常驻横幅）
  setBannerFrozen(true);
  debug('content.js 页面已冻结（评分 ' + result.total + '）');
}

// 解冻（r3 窗口期 + 整页刷新版）：不再就地还原（r2 实测不可靠——
// 还原的 script 重放时页面全局状态已错乱：重复声明、监听器重复注册、
// 被 reject 的 Promise 已走错误分支），改为登记窗口期后 location.reload()
// ——所有 script/iframe/资源完整重新加载，页面状态全新，功能必然正常。
// 窗口期由 background 以 hostname 级记录（默认 30 分钟），刷新后重评
// 命中窗口期则回执 unfrozen 标记：仅注入警示横幅，不再冻结
function unfreezePage() {
  pageUnfrozen = true;
  // 1. 断开 DOM 暂存器与事件拦截（刷新前先恢复基本交互——万一刷新
  //    失败页面也不至于完全卡死；暂存节点无需还原，刷新即重置）
  if (freezeObserver) {
    try { freezeObserver.disconnect(); } catch(e) { /* */ }
    freezeObserver = null;
  }
  if (freezeEventBlocker) {
    for (var bi = 0; bi < FREEZE_BLOCKED_EVENTS.length; bi++) {
      document.removeEventListener(FREEZE_BLOCKED_EVENTS[bi], freezeEventBlocker, true);
    }
    freezeEventBlocker = null;
  }

  // 2~3. 通知 background 登记窗口期，回执后整页刷新。
  //    双保险：消息通道异常（扩展上下文失效等）时 500ms 兜底刷新——
  //    宁可窗口期没记上（刷新后重新冻结，用户再点一次），也不能卡在
  //    冻结态不刷新
  var reloaded = false;
  function doReload() {
    if (reloaded) return;
    reloaded = true;
    try { location.reload(); } catch(e) { /* */ }
  }
  try {
    // 带上当前 URL：background 以 hostname 粒度登记窗口期
    //（sender.tab.url 在同站内导航后可能滞后，location.href 更准）
    chrome.runtime.sendMessage({ action: 'markUnfrozen', url: location.href }, function() {
      void chrome.runtime.lastError; // 通道异常静默：兜底定时器仍会刷新
      doReload();
    });
  } catch(e) { /* sendMessage 抛错：兜底定时器仍会刷新 */ }
  setTimeout(doReload, 500);

  debug('content.js 解冻确认：已登记窗口期，正在整页刷新');
}

// 横幅冻结态切换（r3 无模态版）：
//   on=true  → 横幅加 .frozen 类：显示"已冻结"标签+解冻按钮、隐藏
//              关闭按钮（解冻入口必须常驻）、副文案切为冻结说明
//   on=false → 移除 .frozen：恢复普通警示形态（r3 解冻 = 整页刷新，
//              刷新后重评重新注入普通态横幅，本分支仅防御性保留）
// 冻结态横幅已被用户关闭时重建（普通态尊重用户关闭，冻结态必须有
// 解冻入口）；重评的 fillBannerText 按 bannerFrozenState 保住冻结文案
function setBannerFrozen(on) {
  bannerFrozenState = on;
  if (on && (!warnBannerHostEl || !warnBannerHostEl.isConnected)) {
    // 横幅已被用户关闭：重置注入标记后重建（携带最近评分结果）
    warningBannerInjected = false;
    updateWarningBannerText = null;
    if (lastWarnResult) injectWarningBanner(lastWarnResult);
  }
  if (!warnBannerHostEl || !warnBannerRoot) return;
  try {
    // .frozen 类驱动全部视觉切换（CSS 见横幅模板内 .freeze-row 规则）
    var banner = warnBannerRoot.querySelector('.banner');
    if (banner) banner.classList.toggle('frozen', on);
    // 解冻按钮两段式状态复位（重建横幅场景下按钮为新节点）
    var btn = warnBannerRoot.querySelector('.unfreeze-btn');
    if (btn) {
      btn.classList.remove('confirm');
      btn.textContent = '我已核验，解冻网站';
    }
    // 副文案：冻结/解冻状态说明
    var subEl = warnBannerRoot.querySelector('.sub');
    if (subEl) {
      subEl.textContent = on
        ? '页面已冻结：脚本暂存停用 · 链接与按钮无响应 · 可滚动检查内容'
        : '正在重新加载页面以恢复完整功能…';
    }
  } catch(e) { /* 横幅 DOM 异常时静默：冻结本体（事件拦截+节点暂存）不受影响 */ }
}

// v2.7.0：levenshteinWithin1 / isShortLatinKeyword / shortKeywordBoundaryHit /
// brandDomainKeywordHit 已抽取至 modules/core.js（顶部解构引入）

// ===== localStorage 缓存读取 =====
// 第一阶段（首屏检测）与第三阶段（缓存同步）共用一次读取，
// 避免重复解析；读取失败时退回硬编码兜底列表

function readCachedRules() {
  const result = { domains: HARDCODED_DOMAINS.slice(), cloudWhitelist: [] };
  try {
    const cached = localStorage.getItem('__yh_data');
    if (cached) {
      const data = JSON.parse(cached);
      // 只有缓存里确有域名时才采用，避免空数据覆盖兜底列表
      if (data.domains && data.domains.length > 0) result.domains = data.domains;
      if (data.cloudWhitelist) result.cloudWhitelist = data.cloudWhitelist;
    } else {
      debug('readCachedRules: localStorage 无缓存，使用硬编码兜底');
    }
  } catch(e) {
    debug('readCachedRules: 读取 localStorage 失败: ' + e.message);
  }
  return result;
}

// === 第一阶段：立即重定向检查（同步执行，页面渲染前） ===
(function() {
  let host;
  try {
    host = location.hostname.toLowerCase();
  } catch(e) {
    console.error(LOG_PREFIX + 'content.js 无法获取 hostname:', e);
    return;
  }

  debug('content.js document_start 启动，hostname=' + host);

  if (!host) {
    debug('content.js 跳过：无 hostname（about:blank 等）');
    return;
  }

  // 读取缓存的黑名单与云白名单
  const rules = readCachedRules();
  debug('content.js 首屏使用 ' + rules.domains.length + ' 个黑名单域名');

  // 命中黑名单（云白名单豁免优先）
  const matched = !matchesDomainList(host, rules.cloudWhitelist) &&
    matchesBlockedDomain(host, rules.domains);

  debug('content.js 域名检测结果: host=' + host + ', matched=' + matched);

  // v2.1.0：政府域名本地快筛放行（gov.cn 一律不拦截，与后台 isGovCn 同步）
  if (matched && isGovCnHostname(host)) {
    debug('content.js 跳过（gov.cn 政府域名豁免）');
    return;
  }

  if (matched) {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.id) {
      console.error(LOG_PREFIX + 'content.js chrome.runtime 不可用，无法构造警告页 URL');
      return;
    }
    // 本地跳转警告页（database 立即拦 / iframe 兜底 / noBadge 消息失败兜底）。
    // v2.1.0 修正：不再附加 virus=1——域名匹配无"下载病毒"检测依据
    function localReplace() {
      try {
        const warningUrl = chrome.runtime.getURL('warning.html') +
          '?url=' + encodeURIComponent(location.href) +
          '&t=' + Date.now();
        location.replace(warningUrl);
      } catch(e) {
        console.error(LOG_PREFIX + 'content.js 重定向失败: ' + e.message);
      }
    }

    // 二次确认：白名单/开关状态以 background 缓存为准（本地缓存可能过期）。
    // v2.1.0：回执附带 reason——database（黑名单库，高置信）保持立即拦截；
    // pattern（模式域名，误报主源）改为等 DOM 加载后扫描官方标识再决定
    chrome.runtime.sendMessage({ action: 'checkPage', url: location.href }, function(result) {
      if (chrome.runtime.lastError || !result || !result.blocked) return;

      if (result.reason !== 'pattern') {
        // database：黑名单数据库命中，立即拦截（不参与官方标识豁免）
        localReplace();
        return;
      }

      // ---- pattern：官方标识检测流程（v2.1.0 降误报核心路径）----
      // 立即上报 patternAlive 告知后台已接手（后台据此等页面加载完成，
      // 不设短超时抢跳，见 PATTERN_TOTAL_TIMEOUT / onCompleted 逻辑）
      try {
        chrome.runtime.sendMessage({ action: 'patternAlive', url: location.href },
          function() { void chrome.runtime.lastError; });
      } catch(e) { /* */ }

      // 仅顶级框架走 tab 级协议（officialBadgeFound/noBadge 消息）；
      // iframe 只做本地决策（location.replace 仅替换 iframe 自身，
      // 不能因 iframe 命中把整个宿主页送进警告页）
      const isTop = (window.top === window);

      onDomReadyThen(function() {
        // 第一轮（DOMContentLoaded）：官方标识若已在 DOM 则尽早放行，
        // 用户体验最好（页面刚渲染出来就确认了身份）
        if (detectOfficialBadge()) {
          if (isTop) {
            try {
              chrome.runtime.sendMessage({ action: 'officialBadgeFound' },
                function() { void chrome.runtime.lastError; });
            } catch(e) { /* */ }
            injectVerifyCard('pattern');
          }
          debug('content.js pattern 命中但检出官方标识（DOM 就绪轮），已放行');
          return;
        }

        // DOM 就绪时未检出标识：iframe 无"等加载完"的体验诉求
        //（内嵌资源位，立即替换自身），顶级框架则等页面完全加载
        if (!isTop) { localReplace(); return; }

        // 第二轮（window load）：等页面连同图片/脚本全部加载完再做最终
        // 决策——页脚标识常随资源晚插入，且加载期间页面保持可见，
        // 不会"看一半被跳走"（v2.1.0 按用户要求改为加载完成后拦截）
        onWindowLoaded(function() {
          if (detectOfficialBadge()) {
            try {
              chrome.runtime.sendMessage({ action: 'officialBadgeFound' },
                function() { void chrome.runtime.lastError; });
            } catch(e) { /* */ }
            injectVerifyCard('pattern');
            debug('content.js pattern 命中但检出官方标识（load 轮），已放行');
            return;
          }
          // 第三轮（v2.1.1 动态观察窗）：load 时仍未见标识，启动
          // MutationObserver 持续监视 DOM 5 秒——很多事业单位官网的
          // 标识由异步脚本/AJAX 在 load 后才插入，只查两轮会误拦正规站
          //（观察窗时长与后台 onCompleted 后的 PATTERN_COMPLETED_GRACE
          //  对齐，超时拦截由后台兜底定时器与本地 fallbackTimer 双保险）
          var found = false;
          // 本地兜底：仅在后台消息全挂（扩展上下文失效）时生效
          var fallbackTimer = setTimeout(localReplace, 8000);
          var badgeObserver = new MutationObserver(function() {
            if (found || !detectOfficialBadge()) return;
            found = true;
            badgeObserver.disconnect();
            clearTimeout(fallbackTimer);
            try {
              chrome.runtime.sendMessage({ action: 'officialBadgeFound' },
                function() { void chrome.runtime.lastError; });
            } catch(e) { /* */ }
            injectVerifyCard('pattern');
            debug('content.js pattern 命中但检出官方标识（观察窗轮），已放行');
          });
          badgeObserver.observe(document.documentElement,
            { childList: true, subtree: true });
          // 观察窗结束（5 秒）：仍未检出标识，上报 noBadge 由后台拦截。
          // 后台兜底定时器可能已抢先触发（存在 redirectingTabs 防抖，
          // 双通道不会重复跳转，互为冗余保险）
          setTimeout(function() {
            badgeObserver.disconnect();
            if (found) return;
            try {
              chrome.runtime.sendMessage({ action: 'noBadge' }, function() {
                // 后台已执行拦截跳转（页面即将卸载），取消本地兜底
                if (!chrome.runtime.lastError) clearTimeout(fallbackTimer);
              });
            } catch(e) { /* 保留兜底定时器 */ }
          }, 5000);
        });
      });
    });
  }

  debug('content.js 首屏域名检查完成');
})();

// === 第二阶段（v2.1.2 已移除）：51.la SDK 单特征整页拦截 ===
// 旧逻辑：页面只要引用 sdk.51.la/js-sdk-pro.min.js 就立即上报 blockPage
// 将整页送进拦截流程。误报根因（v2.1.2 误报治理核心修复）：
// 51.la 是国内老牌免费统计服务（对标百度统计），数十万正规网站在用
// 同一标准脚本——银狐样本用它做统计 ≠ 引用它的站点都是恶意站。
// 单一统计脚本特征不足以支撑"整页拦截"这一高代价动作。
// 现处理方式：51.la 保留为评分引擎的 resource 类指标（sdk51，+15 分），
// 是否拦截由综合评分 + 证据多样性 + 分层策略统一裁决（见 scorePage）
// === 第三阶段：监听 MAIN world 拦截事件 + 同步黑名单到 localStorage ===
(function() {
  // 监听主世界拦截器派发的自定义事件，转发给 background 处理跳转
  try {
    window.addEventListener('__yh_block', function(e) {
      const data = e.detail || {};
      debug('content.js 收到拦截事件 url=' + data.url + ' page=' + data.page);
      chrome.runtime.sendMessage({
        action: 'blockPage',
        url: data.url || '',
        fromUrl: data.page || '',
        extId: data.extId || ''
      }, function() { void chrome.runtime.lastError; });
    });
  } catch(e) {
    console.warn(LOG_PREFIX + 'content.js 注册 __yh_block 监听失败: ' + e.message);
  }

  // ---- 黑名单缓存同步 ----
  // 修复说明：旧版这里会先用硬编码 2 条域名覆盖 localStorage，
  // 在 background 回调返回前存在"防护真空窗口"。现在先沿用现有缓存，
  // 仅在拿到完整数据后才写入。

  // 从现有缓存初始化（而非硬编码默认值），避免降级覆盖
  const current = readCachedRules();
  let blockedDomains = current.domains;
  let cloudWhitelist = current.cloudWhitelist;

  // v2.6.1：localStorage 写入失败分级告警。沙箱文档（无 allow-same-origin
  // 的 iframe——DeepSeek 等站点把应用嵌在 sandbox iframe 里，本扩展
  // all_frames:true 会进入其中）访问 localStorage 必然抛 SecurityError，
  // 这是预期降级路径而非故障：该缓存只服务本帧首屏黑名单快筛
  //（readCachedRules），不可用时自动落回硬编码兜底 + 后台二次确认，
  // 无任何功能影响。首次失败降级为 debug（生产环境静默），不再用
  // console.warn 刷 chrome://extensions 错误面板；其余异常（配额满等
  // 真实故障）保留告警，同样只报一次防刷屏
  let lsWriteWarned = false;
  function syncToLocal() {
    try {
      localStorage.setItem('__yh_data', JSON.stringify({
        domains: blockedDomains,
        cloudWhitelist: cloudWhitelist,
        extId: chrome.runtime.id
      }));
      debug('content.js localStorage 已更新: ' + blockedDomains.length + ' 个域名');
    } catch(e) {
      const msg = String((e && e.message) || e || '');
      const sandboxed = (e && e.name === 'SecurityError') || /sandbox/i.test(msg);
      if (!lsWriteWarned) {
        lsWriteWarned = true;
        if (sandboxed) debug('content.js localStorage 不可用（沙箱文档），黑名单缓存写入按预期跳过: ' + msg);
        else console.warn(LOG_PREFIX + 'content.js localStorage 写入失败（仅提示一次）: ' + msg);
      }
    }
  }

  debug('content.js 向 background 请求完整黑名单...');
  chrome.runtime.sendMessage({ action: 'getBlocklist' }, function(r) {
    if (chrome.runtime.lastError) {
      console.warn(LOG_PREFIX + 'content.js getBlocklist 回调错误: ' + chrome.runtime.lastError.message);
    }
    if (r && r.domains) {
      debug('content.js 收到 background 返回的 ' + r.domains.length + ' 个黑名单域名');
      // 以后台数据为准整体替换（而非合并），避免已下线的陈旧域名滞留缓存；
      // 替换后再补硬编码兜底域名
      blockedDomains = r.domains.slice();
      for (let i = 0; i < HARDCODED_DOMAINS.length; i++) {
        if (blockedDomains.indexOf(HARDCODED_DOMAINS[i]) === -1) {
          blockedDomains.push(HARDCODED_DOMAINS[i]);
        }
      }
      cloudWhitelist = r.cloudWhitelist || [];
      syncToLocal();
    } else {
      console.warn(LOG_PREFIX + 'content.js background 未返回有效黑名单');
    }
  });

  // 接收 background 的规则更新广播，实时刷新本地缓存
  chrome.runtime.onMessage.addListener(function(msg) {
    if (msg.action === 'updateBlocklist' && msg.domains) {
      debug('content.js 收到黑名单更新广播: ' + msg.domains.length + ' 个域名');
      blockedDomains = msg.domains;
      cloudWhitelist = msg.cloudWhitelist || cloudWhitelist;
      // 确保硬编码兜底域名始终在列
      for (let i = 0; i < HARDCODED_DOMAINS.length; i++) {
        if (blockedDomains.indexOf(HARDCODED_DOMAINS[i]) === -1) {
          blockedDomains.push(HARDCODED_DOMAINS[i]);
        }
      }
      syncToLocal();
    }
  });
})();

// === 第四阶段：页面评分引擎（v2.0.0 新增，仅顶级窗口运行） ===
// 30 项风险指标加权评分，DOM/资源变化时防抖重评，
// 结果上报 background（scorePage 消息），由后台做最终拦截决策。
// popup 也可通过 getPageScore 消息主动查询当前页评分
(function() {
  // iframe 中不评分（与 2.0.0 保持一致，避免重复上报与跨框架干扰）
  if (window.top !== window) return;

  // 运行时改写过的下载链接集合（"多个下载链接运行时改写"指标用）
  var changedDownloadLinks = new Set();
  // 上次上报的指纹（总分 + 各项命中位图），结果不变则不重复上报
  var lastReportKey = '';
  // 防抖定时器句柄
  var timer = null;
  // 官方标识检测结果缓存（v2.1.1 性能优化，外部审查指出：
  // 评分由 DOM 变化高频触发——防抖 150ms 后仍可能密集执行，
  // detectOfficialBadge 的全量链接/图片遍历不必每次重跑）。
  // null = 已失效需重算；DOM 一旦变化由 observer 回调置空
  var officialBadgeCache = null;
  // 品牌库配置（由 background 下发，品牌冒充检测用）
  var brandConfig = [];
  // 品牌库就绪 Promise：评分前等待配置到位（异常时立即放行，不阻塞引擎）
  var brandConfigReady = new Promise(function(resolve) {
    try {
      chrome.runtime.sendMessage({ action: 'getBrandConfig' }, function(response) {
        if (chrome.runtime.lastError) { brandConfig = []; return resolve(); }
        brandConfig = response && Array.isArray(response.brands) ? response.brands : [];
        resolve();
      });
    } catch(e) {
      brandConfig = [];
      resolve();
    }
  });

  // 页面可见文本（innerText 覆盖渲染后内容，评分主语料）
  function visibleText() {
    return String(document.documentElement && document.documentElement.innerText || '');
  }

  // 页面引用的全部资源 URL（性能条目 + DOM 属性双通道，尽量覆盖懒加载）
  function allResourceUrls() {
    var urls = [];
    try {
      performance.getEntriesByType('resource').forEach(function(entry) { urls.push(entry.name); });
    } catch(e) { /* */ }
    document.querySelectorAll('[src], link[href]').forEach(function(el) {
      var value = el.src || el.href;
      if (value) urls.push(value);
    });
    return urls;
  }

  // 核心评分函数：对当前页面做 30 项风险指标加权评分
  function scorePage() {
    var text = visibleText();
    // 标题 + meta 描述/关键词，与正文合并作为分析语料
    var metaText = [document.title]
      .concat(Array.from(document.querySelectorAll('meta[name="description"], meta[name="keywords"]'))
        .map(function(meta) { return meta.content || ''; }))
      .join(' ');
    var analysisText = text + ' ' + metaText;
    // "下载软件"语境：标题含"下载"且 meta 提到软件/客户端等（多项指标的限定条件）
    var softwareDownloadContext = /下载/.test(document.title) && /软件|客户端|浏览器|助手/.test(metaText);
    // 多品牌软件目录站识别（正规下载站豁免部分激进指标）：
    // 命中 ≥2 个品牌关键词 + ≥8 个目录条目结构
    var catalogBrandCount = brandConfig.filter(function(rule) {
      return (rule.keywords || []).some(function(keyword) {
        return analysisText.toLowerCase().includes(String(keyword).toLowerCase());
      });
    }).length;
    var catalogEntryCount = document.querySelectorAll(
      'a[href*="/detail/"][title], [data-id][data-hottag*="download"]'
    ).length;
    var softwareCatalog = catalogBrandCount >= 2 && catalogEntryCount >= 8;
    var resources = allResourceUrls();
    var details = [];
    var total = 0;

    // v2.1.2 证据类别登记表（误报治理）：30 项指标归入 5 个证据类别——
    //   domain    域名形态（连字符域名模式等）
    //   resource  资源行为（加载特征 SDK/外部统计等）
    //   speech    话术文案（官方/安全/正版话术、密集安全承诺）
    //   structure 页面结构（下载入口形态、SEO 痕迹、反调试等）
    //   brand     品牌冒充（品牌关键词与域名不符及其衍生特征）
    // 硬拦截要求命中 ≥2 个类别：正规站的风险特征往往集中在单一类别
    // （如纯文案话术或纯 SEO 结构），单类别堆分不足以定性为恶意
    var matchedCategories = Object.create(null);
    // v2.6.0：各类别正分累计器——话术类证据封顶计算用（见下方 speechCap）
    var categoryPositivePts = Object.create(null);

    // 评分项累加器：命中加分并记录明细（供弹窗/警告页逐项展示）。
    // v2.1.2：新增 category 参数——命中的正分项同时登记证据类别；
    // 负分项（备案格式/可信分发）不计类别（正向抵扣与证据无关）
    function add(id, label, points, matched, evidence, category) {
      details.push({ id: id, label: label, points: matched ? points : 0, matched: matched, evidence: evidence || '' });
      if (matched) {
        total += points;
        if (category && points > 0) {
          matchedCategories[category] = true;
          categoryPositivePts[category] = (categoryPositivePts[category] || 0) + points;
        }
      }
    }

    // ---- 资源类指标 ----
    // 银狐木马指定的 51.la 统计 SDK。
    // v2.1.2：+10 → +15 并降级为纯评分信号——51.la 是正规统计服务，
    // 单特征不再触发整页拦截（原第二阶段已移除），仅参与综合评分
    var hasSdk = resources.some(function(raw) {
      try {
        var url = new URL(raw, location.href);
        return url.hostname.toLowerCase() === 'sdk.51.la' && url.pathname === '/js-sdk-pro.min.js';
      } catch(e) { return false; }
    });
    add('sdk51', '加载 51.la 指定 SDK', 15, hasSdk, hasSdk ? 'sdk.51.la/js-sdk-pro.min.js' : '', 'resource');

    // ---- 域名形态指标 ----
    // 主域含连字符的可疑后缀域名 *.com.cn/*.hl.cn/*.cc。
    // v2.1.2：+30 → +15——连字符域名正规企业同样注册使用（如跨国公司
    // 中英拼接品牌名），形态可疑但不构成强证据，降权参与综合评分
    var host = location.hostname.toLowerCase().replace(/^\.+|\.+$/g, '');
    var labels = host.split('.');
    var patternDomain = (labels.length >= 3 && labels[labels.length - 1] === 'cn' &&
      (labels[labels.length - 2] === 'com' || labels[labels.length - 2] === 'hl') &&
      labels[labels.length - 3].includes('-')) ||
      (labels.length >= 2 && labels[labels.length - 1] === 'cc' &&
      labels[labels.length - 2].includes('-'));
    add('patternDomain', '连字符 com.cn/hl.cn/cc 域名', 15, patternDomain, patternDomain ? host : '', 'domain');

    // v2.3.0：可信 AI 对话平台识别（豁免表见文件顶部 AI_CHAT_PLATFORM_DOMAINS）。
    // v2.4.0：UGC 平台（bilibili/weibo 等帖子·评论·弹幕语料）同列豁免，
    // 合并为 isTrustedContentPlatform 统一门控。
    // 影响范围：manyEmoji / officialSpeech / ICP 三通道（下方）/ 品牌匹配；
    // 黑名单与强特征（noah/adseo）检测不受影响
    var isAiChatPage = isAiChatHostname(host);
    var isUgcPage = isUgcHostname(host);
    var isSecForumPage = isSecurityForumHostname(host);
    var isTrustedContentPlatform = isAiChatPage || isUgcPage || isSecForumPage;

    // ---- 话术类指标 ----
    // "官方/安全/正版"三类话术齐备。
    // v2.1.2：+20 → +15——正规软件官网普遍使用同类文案（官网标配话术），
    // 三词齐备只能说明"像官网"，不能说明"假官网"
    // v2.3.0a：AI 对话页豁免——这三个词是用户提问与模型输出里的普通词汇
    //（"这是正版官网，安全下载"是对话常态），在 AIGC/UGC 语料下不构成证据
    // v2.4.0：UGC 平台同列豁免——帖子正文/评论出现这些词同样是普通表达
    // 否定语境计数："非官方网站"、"并不安全"、"与正版无关"这类表述是对话术
    // 的反驳而非使用，直接 includes 会把评测文章、粉丝站声明、对比测评全部误计。
    // v2.6.0：前缀否定（非/并非/不/没(有)/无 + 可选助词 是/所谓/会/能/要）
    // 与后缀否定（X+无关）两种构造都剔除，全部被否定的词不再参与判定。
    // "不保证安全"这类词距较远的否定刻意不处理——防把正面承诺误剔，
    // 且该指标本身还有下载语境与次数门槛兜底
    function unnegatedCount(haystack, word) {
      var totalHits = haystack.split(word).length - 1;
      if (!totalHits) return 0;
      var negated = 0;
      try {
        var pre = new RegExp('(?:非|并非|不|没有|没|无)(?:是|所谓|会|能|要)?\\s*' + word, 'g');
        negated += (haystack.match(pre) || []).length;
        var post = new RegExp(word + '\\s*无关', 'g');
        negated += (haystack.match(post) || []).length;
      } catch(e) { return totalHits; }
      return Math.max(0, totalHits - negated);
    }
    var speechCounts = ['官方', '安全', '正版'].map(function(word) {
      return { word: word, count: unnegatedCount(analysisText, word) };
    });
    var speechKinds = speechCounts.filter(function(item) { return item.count > 0; })
      .map(function(item) { return item.word; });
    add('officialSpeech', '官方、安全、正版三类话术', 15,
      !isTrustedContentPlatform && !softwareCatalog && speechKinds.length >= 3,
      speechCounts.filter(function(item) { return item.count > 0; })
        .map(function(item) { return item.word + '×' + item.count; }).join('、'),
      'speech');

    // noah 系域名的 /api.php（银狐木马通信特征，+100 强特征：
    // 特异性极高，单项命中即可硬拦截，不受证据多样性约束）
    var hasNoahApi = resources.some(function(raw) {
      try {
        var url = new URL(raw, location.href);
        return url.hostname.toLowerCase().includes('noah') && url.pathname.toLowerCase() === '/api.php';
      } catch(e) { return false; }
    });
    add('noahApi', '加载 noah 域名的 /api.php', 100, hasNoahApi, hasNoahApi ? 'noah + /api.php' : '', 'resource');

    // 多个下载链接在运行时被脚本改写（占位符 → 真实地址，+20）
    add('rewrittenDownloads', '多个下载链接运行时改写', 20,
      changedDownloadLinks.size >= 2, changedDownloadLinks.size + ' 个', 'structure');

    // ---- 内嵌脚本特征指标 ----
    // 汇总全部内联 <script> 文本（多项指标共用）
    var inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
      .map(function(script) { return script.textContent || ''; }).join('\n');

    // adseo.com.cn 资源引用（+100 强特征：银狐特异 C2/分发域，
    // 单项命中即可硬拦截，不受证据多样性约束）
    var adseoResource = '';
    resources.some(function(raw) {
      try {
        var resourceHost = new URL(raw, location.href).hostname.toLowerCase();
        if (resourceHost === 'adseo.com.cn' || resourceHost.endsWith('.adseo.com.cn')) {
          adseoResource = raw;
          return true;
        }
      } catch(e) { /* */ }
      return false;
    });
    if (!adseoResource) {
      // 资源列表没有时再查内联脚本里的字符串引用
      var adseoMatch = inlineScripts.match(/https?:\/\/[a-z0-9.-]*adseo\.com\.cn(?:[\/:?#][^'"\s)]*)?/i);
      if (adseoMatch) adseoResource = adseoMatch[0];
    }
    add('adseoResource', '加载 adseo.com.cn', 100, !!adseoResource, adseoResource, 'resource');

    // 脚本集中的统一下载地址（GLOBAL_DOWNLOAD_URL 常量 + /download.php?id= 形态，+40）
    var globalDownloadMatch = inlineScripts.match(/GLOBAL_DOWNLOAD_URL\s*=\s*(['"])(https?:\/\/.*?)\1/i);
    var scriptedDownloadUrl = globalDownloadMatch ? globalDownloadMatch[2] : '';
    var scriptedEndpoint = false;
    try {
      var scriptedUrl = new URL(scriptedDownloadUrl);
      scriptedEndpoint = /\/download\.php$/i.test(scriptedUrl.pathname) && scriptedUrl.searchParams.has('id');
    } catch(e) { /* */ }
    add('scriptedDownloadEndpoint', '脚本集中下载地址', 40,
      scriptedEndpoint, scriptedEndpoint ? scriptedDownloadUrl : '', 'structure');

    // 多个占位按钮共用脚本下载地址（+30）
    var scriptedPlaceholderCount = Array.from(document.querySelectorAll('a[href^="javascript:"]'))
      .filter(function(link) {
        return /GLOBAL_DOWNLOAD_URL/.test(link.getAttribute('onclick') || '') &&
          /下载|download|安装包|store|访问/i.test(String(link.innerText || link.textContent || ''));
      }).length;
    add('scriptedDownloadButtons', '多个占位按钮共用脚本下载地址', 30,
      scriptedEndpoint && scriptedPlaceholderCount >= 2, scriptedPlaceholderCount + ' 个', 'structure');

    // 反开发者模式：禁用右键 / 拦截 F12/Ctrl+Shift+I / debugger 陷阱。
    // v2.1.2：+20 → +10 且要求 ≥2 个信号同时出现——国内正规站普遍
    // 禁用右键（图片保护/防复制），单个信号是主流运营行为而非恶意特征
    var antiDeveloperSignals = [];
    if (/contextmenu[\s\S]{0,160}(?:preventDefault\s*\(|return\s+false)|oncontextmenu\s*=\s*(?:function[^}]*return\s+false|[^;]*false)/i.test(inlineScripts)) {
      antiDeveloperSignals.push('禁用右键菜单');
    }
    if (/(?:keyCode|which)\s*={1,3}\s*123|(?:key|code)\s*={1,3}\s*['"]F12['"]|(?:ctrlKey|metaKey)[\s\S]{0,160}(?:shiftKey[\s\S]{0,80})?(?:key|keyCode)\s*={1,3}\s*['"]?(?:i|j|c|u|73|74|67|85)['"]?/i.test(inlineScripts)) {
      antiDeveloperSignals.push('拦截开发者快捷键');
    }
    if (/\bdebugger\s*;/.test(inlineScripts)) antiDeveloperSignals.push('Debugger 陷阱');
    add('antiDeveloper', '反开发者模式', 10,
      antiDeveloperSignals.length >= 2, antiDeveloperSignals.join('、'), 'structure');

    // ---- 下载入口结构指标 ----
    // 多个下载入口（非目录站的"下载软件"语境下 ≥2 个）。
    // v2.1.2：+20 → +10——软件官网提供多平台多入口下载是正常产品行为
    var downloadLinks = Array.from(document.querySelectorAll('a[href], button, [role="button"]'))
      .filter(function(el) { return /下载|download/i.test(String(el.innerText || el.textContent || '')); });
    add('downloadEntrances', '多个下载入口', 10,
      !softwareCatalog && softwareDownloadContext && downloadLinks.length >= 2, downloadLinks.length + ' 个', 'structure');

    // 多个不同平台入口指向同一 ZIP 包（+40）
    var downloadTargets = Object.create(null);
    Array.from(document.querySelectorAll('a[href]')).forEach(function(link) {
      if (!/下载|download|访问/i.test(String(link.innerText || link.textContent || ''))) return;
      try {
        var target = new URL(link.href, location.href);
        if (!/\.zip$/i.test(target.pathname)) return;
        target.hash = '';
        var context = String(link.parentElement && link.parentElement.innerText || link.innerText || '');
        if (!downloadTargets[target.href]) downloadTargets[target.href] = { count: 0, context: '' };
        downloadTargets[target.href].count++;
        downloadTargets[target.href].context += ' ' + context;
      } catch(e) { /* */ }
    });
    var reusedPackage = '';
    Object.keys(downloadTargets).some(function(target) {
      var item = downloadTargets[target];
      // 平台多样性检测：上下文同时提及 ≥3 种平台却指向同一压缩包
      var platformGroups = [/windows/i, /macos|\bmac\b/i, /linux|ubuntu|debian|centos/i, /android/i, /ios|iphone|ipad/i, /web版|网页版/i];
      var platformCount = platformGroups.filter(function(pattern) { return pattern.test(item.context); }).length;
      if (item.count >= 3 && platformCount >= 3) {
        reusedPackage = item.count + ' 个入口：' + target;
        return true;
      }
      return false;
    });
    add('reusedPackage', '多个不同平台指向同一 ZIP', 40, !!reusedPackage, reusedPackage, 'structure');

    // ---- 品牌匹配计算（提前于依赖它的指标，修复 2.0.0 中的顺序缺陷） ----
    // 标题/meta/主标题命中品牌关键词，且域名既非官方域也非可信分发域 → 判定品牌冒充
    // v2.1.5 分层语料改造：
    //   1) 语料按位置拆分并加分隔符合并——title / h1 / meta 各自规范化后
    //      以 '|' 拼接，防止跨边界子串误命中（旧版直接空格拼接去空白，
    //      title 尾词与 meta 首词会粘成一个假词）
    //   2) 记录命中档位 brandHitTier：标题 <title> 命中 → 3（高档）；
    //      页面主标题 h1 命中 → 2（中档）；仅 SEO 元数据命中 → 1（低档）。
    //      brandMismatch 按档位计 30/20/10 分——仿冒站靠蹭搜索流量生存，
    //      必然把完整品牌名写进 <title>；正文文档/报道只在 meta 或 h1
    //      提及品牌的页面不构成同等冒充证据
    var titleText = document.title || '';
    var brandMatch = null;
    var trustedDistributor = null;
    var primaryHeading = document.querySelector('h1');
    function normalizeBrandText(value) {
      return String(value || '').toLowerCase().replace(/\s+/g, '');
    }
    var normalizedTitleBrandText = normalizeBrandText(titleText);
    var normalizedMetaBrandText = normalizeBrandText(metaText);
    var normalizedHeadingBrandText = normalizeBrandText(primaryHeading && primaryHeading.innerText || '');
    // v2.3.9：短拉丁词（如远程库 LINE 的 "line"）需在未去空格原文上做词边界
    // 复核——"cline"、"online"、"deadline" 都包含 "line"，规范化文本已剥空白
    // 无法判词边界，故保留原文副本传入
    var rawTitleBrandText = String(titleText || '').toLowerCase();
    var rawMetaBrandText = String(metaText || '').toLowerCase();
    var rawHeadingBrandText = String(primaryHeading && primaryHeading.innerText || '').toLowerCase();
    function matchesBrand(rule, haystack, rawHaystack) {
      return (rule.keywords || []).some(function(keyword) {
        var normalizedKeyword = String(keyword).toLowerCase().replace(/\s+/g, '');
        if (!haystack.includes(normalizedKeyword)) return false;
        if (isShortLatinKeyword(normalizedKeyword) &&
            !shortKeywordBoundaryHit(normalizedKeyword, rawHaystack)) return false;
        return true;
      });
    }
    var combinedBrandText = normalizedTitleBrandText + '|' +
      normalizedHeadingBrandText + '|' + normalizedMetaBrandText;
    var combinedRawBrandText = rawTitleBrandText + '|' +
      rawHeadingBrandText + '|' + rawMetaBrandText;
    // v2.1.5：开发者平台与搜索引擎豁免（两表均与 background.js 同名表
    // 两处同步）——平台页面提及品牌是文档/讨论语境，搜索结果页标题
    // 必然包含用户查询的品牌词，均为"提及"而非"冒充"，
    // 命中任一豁免即跳过匹配，使全部 brand 类指标失效。
    // v2.3.0：可信 AI 对话页同列豁免——对话正文/标题高频出现任意品牌词
    //（用户提问即决定），是问答语境而非冒充
    var isDeveloperPlatform = DEVELOPER_PLATFORM_DOMAINS.some(function(platformDomain) {
      return host === platformDomain || host.endsWith('.' + platformDomain);
    });
    var isSearchEngine = SEARCH_ENGINE_DOMAINS.some(function(searchDomain) {
      return host === searchDomain || host.endsWith('.' + searchDomain);
    });
    var matchedBrandRule = (isDeveloperPlatform || isSearchEngine || isTrustedContentPlatform) ? null : brandConfig.find(function(rule) {
      return matchesBrand(rule, combinedBrandText, combinedRawBrandText);
    });
    // 命中档位：3=页面标题 / 2=h1 主标题 / 1=仅 SEO 元数据
    var brandHitTier = 0;
    if (matchedBrandRule) {
      var rule = matchedBrandRule;
      var official = (rule.officialDomains || []).some(function(domain) {
        domain = String(domain).toLowerCase();
        return host === domain || host.endsWith('.' + domain);
      });
      var trusted = (rule.trustedDomains || []).some(function(domain) {
        domain = String(domain).toLowerCase();
        return host === domain || host.endsWith('.' + domain);
      });
      if (trusted) trustedDistributor = rule;
      else if (!official) {
        brandMatch = rule;
        if (matchesBrand(rule, normalizedTitleBrandText, rawTitleBrandText)) brandHitTier = 3;
        else if (matchesBrand(rule, normalizedHeadingBrandText, rawHeadingBrandText)) brandHitTier = 2;
        else brandHitTier = 1;
        // v2.2.0：仅 SEO 元数据命中（tier 1）且标题/h1 无声称词 → 不算冒充。
        // meta keywords 堆品牌词的 SEO 站是分层计分后残留的最大误报源——
        // "提及"≠"冒充"，清空 brandMatch 使全部 brand 类指标随之失效
        if (brandHitTier === 1 &&
            !/官网|官方|正版|下载/.test(
              titleText + ' ' + (primaryHeading && primaryHeading.innerText || ''))) {
          debug('content.js 品牌匹配豁免：仅 SEO 元数据命中且无声称词');
          brandMatch = null;
          brandHitTier = 0;
        }
      }
    }

    // v2.1.2 强信号 A（漏报修复）+ v2.1.3 模糊匹配增强：域名品牌词仿冒。
    // 域名本身包含品牌的英文关键词（如 huorongaq.com 含 "huorong"）
    // 却不在官方域——typosquatting/品牌词拼凑域名，是比页面文案硬得多
    // 的仿冒证据（huorong.cn 才是火绒官方域）。误报面极窄：
    //   - 官方域/可信分发域在前置逻辑已排除（brandMatch 为 null）
    //   - 正规站点域名含品牌词的基本就是品牌方自营（已在 officialDomains）
    //   - 仅匹配 ≥3 字符的纯拉丁关键词（中文词不会出现在域名中）
    // v2.1.3（用户实测 huorrong.com.cn 漏拦指出）：精确子串匹配抓不到
    // 拼写变体——"huorrong"（双写 r）不含子串 "huorong"。新增编辑距离
    // 比对：域名主体与 ≥6 字符关键词的 Levenshtein 距离 ≤1 判定仿冒
    //（覆盖双写/缺写/邻位换序等单字符 typo；≥6 字符词距离 1 的碰撞率
    //  极低，且仍受"页面命中品牌关键词"前置条件约束）
    var domainBrandImpersonation = false;
    if (brandMatch) {
      // 提取域名主体段：取后缀前的一段（处理 com.cn 等双段后缀）——
      // www.huorrong.com.cn → huorrong；www.huorong.cn → huorong；
      // huorongaq.com → huorongaq。子域前缀（www 等）不参与编辑距离
      var hostLabels = host.split('.');
      var registrable = host;
      if (hostLabels.length >= 2) {
        var secondLevel = hostLabels[hostLabels.length - 2];
        var tld = hostLabels[hostLabels.length - 1];
        // 中国双段后缀：com.cn/net.cn/org.cn/gov.cn/edu.cn/ac.cn
        var isCnDouble = tld === 'cn' &&
          ['com', 'net', 'org', 'gov', 'edu', 'ac'].indexOf(secondLevel) !== -1;
        var cut = isCnDouble ? 2 : 1;
        if (hostLabels.length > cut) {
          registrable = hostLabels[hostLabels.length - cut - 1];
        } else {
          registrable = hostLabels[0];
        }
      }
      domainBrandImpersonation = (brandMatch.keywords || []).some(function(keyword) {
        var kw = String(keyword).toLowerCase();
        if (kw.length < 3 || !/^[a-z0-9]+$/.test(kw)) return false;
        // 路径 1：子串包含（huorongaq 含 huorong）；短词需强边界——
        // v2.3.9：cline.bot / linear.app 不再因含 "line" 判为 LINE 仿冒
        if (brandDomainKeywordHit(kw, host, registrable)) return true;
        // 路径 2：编辑距离 ≤1 的拼写变体（huorrong ↔ huorong，仅长词）
        if (kw.length >= 6 && registrable &&
            Math.abs(registrable.length - kw.length) <= 1 &&
            levenshteinWithin1(registrable, kw)) return true;
        return false;
      });
    }

    // 品牌冒充站点多个平台共用无参数下载端点（+40）
    var sharedDownloadEndpoint = '';
    var endpointTargets = Object.create(null);
    Array.from(document.querySelectorAll('a[href]')).forEach(function(link) {
      if (!/下载|download/i.test(String(link.innerText || link.textContent || ''))) return;
      try {
        var target = new URL(link.href, location.href);
        if ((!/\/download\.php$/i.test(target.pathname) && !/\/down\/[^/]+$/i.test(target.pathname)) || target.search) return;
        target.hash = '';
        if (!endpointTargets[target.href]) endpointTargets[target.href] = { count: 0, context: '' };
        endpointTargets[target.href].count++;
        endpointTargets[target.href].context += ' ' + String(link.parentElement && link.parentElement.innerText || link.innerText || '');
      } catch(e) { /* */ }
    });
    Object.keys(endpointTargets).some(function(target) {
      var item = endpointTargets[target];
      var platformGroups = [/windows/i, /macos|\bmac\b/i, /linux|ubuntu|debian|fedora|arch/i, /android/i, /ios|iphone|ipad/i, /智能电视|android tv|fire tv|google tv/i];
      var platformCount = platformGroups.filter(function(pattern) { return pattern.test(item.context); }).length;
      if (brandMatch && item.count >= 3 && platformCount >= 3) {
        sharedDownloadEndpoint = item.count + ' 个平台入口：' + target;
        return true;
      }
      return false;
    });
    add('sharedDownloadEndpoint', '多个平台共用无参数下载端点', 40,
      !!sharedDownloadEndpoint, sharedDownloadEndpoint, 'brand');

    // 外部统计脚本 spst2.com（+20）
    var hasStatsScript = resources.some(function(raw) {
      try { return new URL(raw, location.href).hostname.toLowerCase().endsWith('.spst2.com'); }
      catch(e) { return false; }
    });
    add('externalStats', '外部统计脚本', 20, hasStatsScript, hasStatsScript ? 'spst2.com' : '', 'resource');

    // ---- 结构化数据（JSON-LD）指标 ----
    // SoftwareApplication 结构化数据（SEO 优化痕迹）。
    // v2.1.2 误报治理：+20 → 0（移除计分，仅保留明细展示与数据采集）——
    // 结构化数据是搜索引擎官方推荐的 SEO 最佳实践，正规软件站标配，
    // 不构成风险证据；downloadUrl/ratingCount 仍供后续特异指标使用
    var structuredDownloadUrls = [];
    var structuredRatingCount = 0;
    var hasStructuredData = false;
    Array.from(document.querySelectorAll('script[type="application/ld+json"]')).forEach(function(script) {
      try {
        var data = JSON.parse(script.textContent || 'null');
        // 兼容单对象/数组/@graph 嵌套，BFS 遍历全部节点
        var nodes = Array.isArray(data) ? data : [data];
        while (nodes.length) {
          var node = nodes.shift();
          if (!node || typeof node !== 'object') continue;
          if (node['@type'] === 'SoftwareApplication' || node['@type'] === 'MobileApplication') {
            hasStructuredData = true;
            if (node.downloadUrl) structuredDownloadUrls.push(String(node.downloadUrl));
            if (node.aggregateRating && node.aggregateRating.ratingCount) {
              structuredRatingCount = Math.max(structuredRatingCount, Number(node.aggregateRating.ratingCount) || 0);
            }
          }
          if (Array.isArray(node['@graph'])) nodes = nodes.concat(node['@graph']);
        }
      } catch(e) { /* */ }
    });
    add('structuredSeo', '软件结构化 SEO 数据', 0, hasStructuredData, hasStructuredData ? 'SoftwareApplication（不计分）' : '');

    // 大量 picsum.photos 随机占位图（模板站痕迹，≥5 张 +20）
    var placeholderImageCount = Array.from(document.querySelectorAll('img[src]')).filter(function(image) {
      try { return new URL(image.src, location.href).hostname.toLowerCase() === 'picsum.photos'; }
      catch(e) { return false; }
    }).length;
    add('placeholderImages', '大量随机占位图片', 20,
      placeholderImageCount >= 5, placeholderImageCount + ' 张', 'structure');

    // 站长验证 meta + Canonical 链接同时存在。
    // v2.1.2 误报治理：+20 → 0（移除计分）——两项均为正规 SEO 基础操作
    //（必应站长验证 + 规范化链接），同时存在只说明"做过 SEO"，
    // 而银狐样本使用的是同一套模板站，该特征已被模板类结构指标覆盖
    var hasVerification = !!document.querySelector('meta[name="msvalidate.01"]') && !!document.querySelector('link[rel="canonical"]');
    add('seoTemplate', '站长验证与 Canonical SEO 模板', 0, hasVerification, hasVerification ? '两项同时存在（不计分）' : '');

    // ---- 品牌冒充综合指标（依赖上面的 brandMatch 计算） ----
    // 多品牌软件目录站标记（0 分，仅作其他指标的豁免条件）
    add('softwareCatalog', '多品牌软件目录', 0, softwareCatalog,
      catalogBrandCount + ' 个品牌，' + catalogEntryCount + ' 个目录条目');
    // 品牌可信应用商店分发（-50，负分抵扣，显著降低误报）
    add('trustedDistributor', '品牌可信应用商店分发', -50, !!trustedDistributor,
      trustedDistributor ? trustedDistributor.name + ' + ' + host : '');
    // 品牌冒充（v2.1.5 按命中档位计分：标题 30 / h1 主标题 20 / 仅 SEO 元数据 10）。
    // 后台二次核查（applyBrandCheck）只看得到 <title>，其补检恒为高档 30 分，
    // 与本表最高档一致；content 已检出时后台不重复加分，低档结论得以保留
    var BRAND_TIER_POINTS = [0, 10, 20, 30];
    var BRAND_TIER_LABELS = ['', 'SEO 元数据命中', 'h1 主标题命中', '页面标题命中'];
    add('brandMismatch', '软件品牌与官网域名不匹配', BRAND_TIER_POINTS[brandHitTier] || 0,
      !softwareCatalog && !!brandMatch,
      brandMatch ? brandMatch.name +
        (BRAND_TIER_LABELS[brandHitTier] ? '（' + BRAND_TIER_LABELS[brandHitTier] + '）' : '') : '',
      'brand');
    // v2.1.2：域名品牌词仿冒（+30，brand 类）——计入强信号直接硬拦，
    // 典型案例 huorongaq.com（含 "huorong" 非官方域，页面冒充火绒安全）
    add('domainBrandImpersonation', '域名仿冒品牌关键词', 30,
      !!domainBrandImpersonation,
      domainBrandImpersonation && brandMatch ? brandMatch.name + ' + ' + host : '', 'brand');
    // 品牌冒充 + 可疑域名组合（+20）
    add('brandPatternCombo', '品牌冒充与可疑域名组合', 20,
      !!brandMatch && patternDomain, brandMatch && patternDomain ? brandMatch.name + ' + ' + host : '', 'brand');
    // 品牌冒充并声明官方身份（+20）：
    // 标题/meta 含"官网"等字样，或 author meta 自称品牌方
    var authorMeta = document.querySelector('meta[name="author"]');
    var normalizedAuthor = String(authorMeta && authorMeta.content || '').toLowerCase().replace(/\s+/g, '');
    // v2.3.9：短词词边界复核需未去空格原文
    var rawAuthor = String(authorMeta && authorMeta.content || '').toLowerCase();
    var authorBrandClaim = !!brandMatch && matchesBrand(brandMatch, normalizedAuthor, rawAuthor);
    var officialClaimMismatch = /官网|官方网站|官方下载|官方客户端下载/.test(titleText + ' ' + metaText) || authorBrandClaim;
    add('officialClaimMismatch', '品牌冒充并声明官方身份', 20,
      !softwareCatalog && !!brandMatch && officialClaimMismatch,
      brandMatch && officialClaimMismatch ? brandMatch.name + (authorBrandClaim ? '（作者声明）' : '') : '', 'brand');

    // 结构化下载地址指向搜索引擎门户（+20）
    var searchPortalDownload = '';
    if (brandMatch) structuredDownloadUrls.some(function(raw) {
      try {
        var targetHost = new URL(raw, location.href).hostname.toLowerCase().replace(/^www\./, '');
        if (['bing.com', 'google.com', 'baidu.com', 'sogou.com', 'so.com'].includes(targetHost)) {
          searchPortalDownload = raw;
          return true;
        }
      } catch(e) { /* */ }
      return false;
    });
    add('structuredSearchDownload', '结构化下载地址指向搜索门户', 20,
      !!searchPortalDownload, searchPortalDownload, 'brand');

    // 冒充官网并堆叠权威背书（"清华/信通院"等 ≥2 项，+20）
    var authorityKinds = ['清华大学', '中国信通院', '权威机构', '战略合作伙伴', '联合发布白皮书']
      .filter(function(claim) { return analysisText.includes(claim); });
    var officialSiteClaim = /官网|官方网站/.test(titleText);
    add('authorityEndorsements', '冒充官网并堆叠权威背书', 20,
      !!brandMatch && officialSiteClaim && authorityKinds.length >= 2, authorityKinds.join('、'), 'brand');

    // 异常超大用户与评分数据（宣称亿级用户 + 结构化评分 ≥10 万条，+20）
    var billionUserClaim = /\d+(?:\.\d+)?\s*亿\+?\s*(?:累计装机)?用户/.test(analysisText);
    add('inflatedPopularity', '异常超大用户与评分数据', 20,
      !!brandMatch && officialSiteClaim && structuredRatingCount >= 100000 && billionUserClaim,
      structuredRatingCount + ' 条评分，页面宣称亿级用户', 'brand');

    // ---- 安装包外链滥用指标 ----
    // 汇总全部压缩包/安装包直链（zip/rar/7z/exe/msi/dmg/pkg/apk）
    var packageLinks = Array.from(document.querySelectorAll('a[href]')).filter(function(link) {
      try { return /\.(?:zip|rar|7z|exe|msi|dmg|pkg|apk)$/i.test(new URL(link.href, location.href).pathname); }
      catch(e) { return false; }
    });
    var zipLinks = packageLinks.filter(function(link) {
      try { return /\.zip$/i.test(new URL(link.href, location.href).pathname); }
      catch(e) { return false; }
    });
    // 按目标 URL 分组统计
    var packageTargets = Object.create(null);
    packageLinks.forEach(function(link) {
      try {
        var target = new URL(link.href, location.href);
        target.hash = '';
        var key = target.href;
        if (!packageTargets[key]) packageTargets[key] = { count: 0, labels: [], host: target.hostname.toLowerCase() };
        packageTargets[key].count++;
        packageTargets[key].labels.push(String(link.innerText || link.textContent || '').trim());
      } catch(e) { /* */ }
    });
    // 站内功能链接（帮助/文档/客服等）被伪装成外部安装包（+20）
    var externalPackageAbuse = '';
    if (brandMatch) Object.keys(packageTargets).some(function(target) {
      var item = packageTargets[target];
      var officialTarget = (brandMatch.officialDomains || []).some(function(domain) {
        domain = String(domain).toLowerCase();
        return item.host === domain || item.host.endsWith('.' + domain);
      });
      var disguisedCount = item.labels.filter(function(label) {
        return /帮助|文档|教程|客服|公司|新闻|加入|隐私|政策|条款|地图|关于/.test(label);
      }).length;
      // v2.2.1：按注册域比较——自家下载子域（dl.xxx.com）不算"外部"，
      // 站内功能链接伪装判定的对象是真正跨主域的安装包直链
      if (!isSameSiteHost(item.host, host) && !officialTarget && item.count >= 5 && disguisedCount >= 3) {
        externalPackageAbuse = item.count + ' 个链接（其中 ' + disguisedCount + ' 个非下载功能）：' + target;
        return true;
      }
      return false;
    });
    add('externalPackageAbuse', '站内功能链接伪装为外部安装包', 20,
      !!externalPackageAbuse, externalPackageAbuse, 'brand');

    // 多平台使用外部安装包（安装包域名与站点跨主域，+30）。
    // v2.2.1：按注册域比较——托管在自家下载子域（dl.xxx.com）不算外部
    var externalPlatformPackages = '';
    var packagePlatformGroups = [/windows/i, /macos|\bmac\b/i, /linux|ubuntu|debian|fedora|arch/i, /android/i, /ios|iphone|ipad/i, /智能电视|android tv|fire tv|google tv/i];
    var packageContext = packageLinks.map(function(link) {
      // 优先取下载面板（.download-panel）整体文案作为平台判断上下文
      var panel = link.closest && link.closest('.download-panel');
      return String(panel && panel.innerText || link.parentElement && link.parentElement.innerText || link.innerText || '');
    }).join(' ');
    var packagePlatformCount = packagePlatformGroups.filter(function(pattern) { return pattern.test(packageContext); }).length;
    var externalPackageCount = packageLinks.filter(function(link) {
      try { return !isSameSiteHost(new URL(link.href, location.href).hostname.toLowerCase(), host); }
      catch(e) { return false; }
    }).length;
    // 外部安装包域名去重统计（跨平台安装包分散到多个外部域名指标用）。
    // v2.2.1：同站子域不计入"外部域名"
    var externalPackageHosts = Object.create(null);
    packageLinks.forEach(function(link) {
      try {
        var packageHost = new URL(link.href, location.href).hostname.toLowerCase();
        if (!isSameSiteHost(packageHost, host)) externalPackageHosts[packageHost] = true;
      } catch(e) { /* */ }
    });
    if (brandMatch && packageLinks.length >= 3 && packagePlatformCount >= 3 && externalPackageCount >= 3) {
      externalPlatformPackages = packageLinks.length + ' 个外部安装包，覆盖 ' + packagePlatformCount + ' 个平台';
    }
    add('externalPlatformPackages', '多个平台使用外部安装包', 30,
      !!externalPlatformPackages, externalPlatformPackages, 'brand');
    // 跨平台安装包分散到 ≥2 个外部域名（+20）
    add('diverseExternalPackageHosts', '跨平台安装包分散到多个外部域名', 20,
      !!brandMatch && packagePlatformCount >= 3 && Object.keys(externalPackageHosts).length >= 2,
      Object.keys(externalPackageHosts).length + ' 个外部安装包域名', 'brand');
    // ZIP 压缩包下载（非目录站）。
    // v2.1.2：+10 → +5——开源软件/绿色软件官网直接分发 zip 是常态
    add('archiveDownload', 'ZIP 压缩包下载', 5,
      !softwareCatalog && zipLinks.length > 0, zipLinks.length + ' 个', 'structure');

    // ---- v2.2.0 下载入口指向分析（疑似品牌仿冒场景的放行证据，负分抵扣）----
    // 仅在 brandMatch 存在（疑似品牌仿冒）时评估全部下载/安装入口的目标指向：
    //   全部指向品牌官方域 → -30：用户被送往正版官网（导航站/推荐页场景），无害；
    //   无任何有效下载目标 → -25：自称官网下载但按钮全是占位符/无下载功能——
    //   空壳模板站（套模板蹭搜索流量但没有真实分发行为），配合负分压到阈值以下。
    // 判定口径：
    //   有效目标 = 可解析为 http(s)、非占位符（#/javascript:/空）的目标 URL，
    //   来源覆盖 <a> 安装包直链、结构化数据 downloadUrl、脚本集中下载地址；
    //   指向当前域名的非安装包链接视为站内导航不计入目标；
    //   指向当前域名的安装包直链计入目标（自分发行为阻断"全官方"抵扣）。
    var officialHostList = brandMatch ?
      [].concat(brandMatch.officialDomains || [], brandMatch.trustedDomains || []) : [];
    function isOfficialTargetHost(targetHost) {
      return officialHostList.some(function(domain) {
        domain = String(domain).toLowerCase();
        return targetHost === domain || targetHost.endsWith('.' + domain);
      });
    }
    var dlTargetHostMap = Object.create(null); // "host href" -> host（URL 级去重）
    var dlPlaceholderCount = 0;                // 占位符下载元素计数
    var dlElementCount = 0;                    // 下载语境元素总数
    function addDownloadEntry(raw) {
      raw = String(raw || '').trim();
      if (!raw) return;
      dlElementCount++;
      if (/^javascript:/i.test(raw) || raw === '#') { dlPlaceholderCount++; return; }
      try {
        var target = new URL(raw, location.href);
        if (target.protocol !== 'http:' && target.protocol !== 'https:') {
          dlPlaceholderCount++;
          return;
        }
        dlTargetHostMap[target.hostname.toLowerCase() + ' ' + target.href] =
          target.hostname.toLowerCase();
      } catch(e) { dlPlaceholderCount++; }
    }
    Array.from(document.querySelectorAll('a[href]')).forEach(function(link) {
      var labelText = String(link.innerText || link.textContent || '');
      var hrefAttr = String(link.getAttribute('href') || '');
      var entryPathname = '';
      try { entryPathname = new URL(hrefAttr, location.href).pathname; } catch(e) { /* */ }
      var isPackageHref = /\.(?:zip|rar|7z|exe|msi|dmg|pkg|apk)$/i.test(entryPathname);
      if (!/下载|download|安装包/i.test(labelText) && !isPackageHref) return;
      try {
        var entryTarget = new URL(hrefAttr, location.href);
        // 站内导航链接（同主域 + 非安装包路径）不计入下载目标分析。
        // v2.2.1：按注册域比较，www./dl. 等子域同样视为站内
        if (isSameSiteHost(entryTarget.hostname.toLowerCase(), host) && !isPackageHref) return;
      } catch(e) { /* 解析失败交给 addDownloadEntry 兜底分类 */ }
      addDownloadEntry(hrefAttr);
    });
    structuredDownloadUrls.forEach(addDownloadEntry);
    addDownloadEntry(scriptedDownloadUrl);
    var dlUniqueHosts = [];
    Object.keys(dlTargetHostMap).forEach(function(key) {
      var dlHost = dlTargetHostMap[key];
      if (dlUniqueHosts.indexOf(dlHost) === -1) dlUniqueHosts.push(dlHost);
    });
    // v2.2.0：officialSiteClaim 已在上方赋值（标题含"官网/官方网站"），
    // 空壳站判定限定在自称官网下载的语境下
    var noRealDownload = !!brandMatch && !!officialSiteClaim &&
      dlElementCount > 0 && dlUniqueHosts.length === 0;
    add('noRealDownload', '无实际下载功能', -25, noRealDownload,
      noRealDownload ? dlElementCount + ' 个下载入口均为占位符' : '');
    // v2.2.1：同站子域（dl.xxx.com）中性处理——既不算"外部安装包"加分
    // （上方已按注册域比较），也不参与本项 -30 抵扣。抵扣只针对
    // 规则库品牌官方域/可信域，同站分发是常态、不构成额外信任证据
    var allOfficialDownloads = !!brandMatch && dlUniqueHosts.length > 0 &&
      dlUniqueHosts.every(isOfficialTargetHost);
    add('officialDownloads', '下载入口全部指向品牌官方域', -30, allOfficialDownloads,
      allOfficialDownloads ? dlUniqueHosts.slice(0, 3).join('、') : '');

    // ---- 文案密度指标 ----
    // 密集安全承诺（"安全"出现 ≥10 次 + 下载软件语境）。
    // v2.1.2：+30 → +15 且门槛 5 次 → 10 次——安全类软件官网
    // "安全"一词天然高频（产品文案本身就是安全叙事），5 次过于宽松
    var safetyCount = (analysisText.match(/安全/g) || []).length;
    add('safetyClaims', '密集安全承诺', 15,
      !softwareCatalog && softwareDownloadContext && safetyCount >= 10, safetyCount + ' 次', 'speech');

    // 大量表情符号（低质模板站特征，+20）。
    // v2.6.0 语料收紧：只统计**作者语料**（<title> / <h1> / meta 描述关键词）里的
    // 表情——评论区、留言板、UGC 区块的表情是访客行为不是站点特征，旧版对
    // 整页 visibleText 计数导致带热评的文章页误报；阈值 6→5（语料变短）。
    // 类别从 structure 迁移到 speech：表情堆砌本质是文案观感信号，归入
    // structure 曾使"纯文案模板站"凑出 hasHardEvidence（冻结门槛）与
    // 多类别硬拦截，是冻结误报的隐性来源之一
    // v2.3.0：AI 对话页豁免——AI 回复天然高频使用表情符号，此指标在对话页失真
    var authorEmojiText = [document.title,
      primaryHeading ? (primaryHeading.innerText || '') : '', metaText].join(' ');
    var emojiCount = 0;
    try { emojiCount = (authorEmojiText.match(/\p{Extended_Pictographic}/gu) || []).length; } catch(e) { /* */ }
    add('manyEmoji', '大量表情符号', 20,
      !isTrustedContentPlatform && emojiCount >= 5,
      emojiCount + ' 个（标题/主标题/描述语料）', 'speech');

    // 大量内嵌 CSS 及注释（AI 生成模板痕迹，+10）
    var inlineCss = Array.from(document.querySelectorAll('style')).map(function(el) { return el.textContent || ''; }).join('\n');
    var cssRuleCount = (inlineCss.match(/{/g) || []).length;
    var cssCommentCount = (inlineCss.match(/\/\*/g) || []).length;
    var cssMatched = cssRuleCount > 10 && cssCommentCount > 10;
    add('inlineCss', '大量内嵌 CSS 及注释', 10, cssMatched,
      cssRuleCount + ' 个规则块，' + cssCommentCount + ' 条注释', 'structure');

    // ---- ICP 备案号核验（v2.1.3 重写，参考开源项目 icp-utils）----
    // 旧版缺陷（用户实测指出）：正则 [A-Z0-9-]{5,} 允许纯字母——
    // 模板占位符"京ICP备XXXXXXXX号"被判定为合法备案格式拿到 -10 分，
    // 且伪造检查只查顺序数字（12345678），字母占位符完全逃逸。
    // 新版三重校验（参考 VirusDetector 开源项目的 ICP_BLACKLIST 设计）：
    //   1. 格式严格化：31 个省份简称白名单 + ICP备/证 + 纯数字 6-12 位 + 号(-分主体)
    //   2. 伪造黑名单：字母占位符（XXXX）、全零段、顺序数字、10000000 演示段
    //   3. 权重分级（用户需求）：链接到工信部备案系统且格式合规 → -20（高可信，
    //      仿冒站极少费功夫做真链接）；仅纯文本声明 → -5（低可信，钓鱼站盗用
    //      他人备案号写进页脚是常见操作）
    var icpLinkedMatch = null;
    var icpTextMatch = null;
    var ICP_REGEX = new RegExp('[' + '京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁' + ']ICP[备证]\\d{6,12}号(?:-\\d+)?', 'i');
    var icpIsFakeNumber = function(num) {
      if (!num) return true;
      // 数字段拼接（"京ICP备12345678号-1" → "123456781"，主段校验取前 12 位即可）
      var digits = (num.match(/\d+/g) || []).join('');
      if (!digits) return true;                          // 无数字：字母占位符（XXXXXXXX 等）
      if (/^0{6,}/.test(digits)) return true;            // 全零段（00000000）
      if (digits.indexOf('10000000') !== -1) return true; // 演示占位段（各模板站通用假号）
      var asc = '01234567890123456789';
      var desc = '98765432109876543210';
      if (digits.length >= 6 && (asc.indexOf(digits) !== -1 || desc.indexOf(digits) !== -1)) return true; // 顺序数字
      return false;
    };
    // v2.3.0：AI 对话页 ICP 豁免——对话内容（AIGC/UGC）可能包含用户粘贴的
    // 任意备案号文本，页面脚注备案属于平台而非对话内容，三通道整体跳过；
    // icpClaimed 恒为 false → 后台跳过 ICP API 核验，"声明备案但查无记录"
    // 的盗用备案 +20/+30 惩罚不会落在平台头上。
    // v2.4.0：UGC 平台同列豁免——帖子里粘贴的备案号同样是内容而非页脚声明
    if (!isTrustedContentPlatform) {
      // 通道一（高可信）：指向工信部备案系统的链接文本中提取合规备案号
      try {
        var beianLinks = document.querySelectorAll('a[href*="beian.miit.gov.cn"], a[href*="beian.miit.gov"]');
        for (var bi = 0; bi < beianLinks.length && !icpLinkedMatch; bi++) {
          var bm = (beianLinks[bi].textContent || '').match(ICP_REGEX);
          if (bm && !icpIsFakeNumber(bm[0])) icpLinkedMatch = bm[0];
        }
      } catch(e) { /* */ }
      // 通道二（低可信）：页面文本兜底扫描（不含链接通道时才生效）
      if (!icpLinkedMatch) {
        var tm = analysisText.match(ICP_REGEX);
        if (tm && !icpIsFakeNumber(tm[0])) icpTextMatch = tm[0];
      }
    }
    // 声明备案标记：供 background 的 ICP API 异步核验使用（页面声明了备案
    // 但 API 查无 → 伪造备案，+20 分升级风险，见 background enhanceScoreAsync）
    var icpClaimed = !!(icpLinkedMatch || icpTextMatch);
    add('icpLinked', '工信部备案链接', -20, !!icpLinkedMatch, icpLinkedMatch || '');
    add('icpTextOnly', '文本备案声明', -5, !!icpTextMatch, icpTextMatch || '');

    // v2.1.0：官方标识检测（CONAC 等）——评分已达阈值但页面挂有
    // 党政机关/事业单位标识时，后台将放行本页并回执豁免标记，
    // 由本脚本注入悬浮验证卡片（降误报）。
    // v2.1.1：走结果缓存——DOM 未变化时复用上次结论，避免每次
    // 评分都全量遍历链接/图片；缓存由 observer 在 DOM 变化时置空
    if (officialBadgeCache === null) officialBadgeCache = detectOfficialBadge();
    var officialBadge = officialBadgeCache;

    // v2.1.2 分层拦截阈值（误报治理）：
    //   硬拦截线 150：总分 ≥150 且证据类别 ≥2（或强特征单项命中）才跳警告页；
    //   软拦截线 100：总分 100~149 不跳页，仅由 content 注入顶部警示横幅，
    //                浏览不中断、用户自行判断（误报代价从"无法访问"降为"一条提示"）
    // 强特征（单项命中即硬拦截，不受证据多样性约束）：
    //   v2.2.0 收紧为仅限已知恶意基础设施：noahApi / adseoResource（各 +100，
    //   银狐特异通信/分发域）。品牌仿冒类信号不再直拦：
    //     - domainBrandImpersonation（域名含品牌词）：保留 +30 计分，参与综合裁决；
    //     - hasSdk && brandMatch && 有下载入口的模板指纹组合：改为显式计分项
    //       templateFingerprint（+40，structure 类），见下方 add()。
    // v2.6.0 纯话术类证据封顶：speech 类（官方/安全/正版话术、密集安全承诺、
    // 表情符号）全部命中也只有 50 分，却能靠叠加把正规站推上 notice/card 层。
    // 文案观感永远不该单独构成拦截理由——超过上限的部分不再计入总分并
    // 明示抵扣明细；结构/资源/域名/品牌类正分不受影响
    var SPEECH_CAP_PTS = 25;
    var speechPts = categoryPositivePts.speech || 0;
    if (speechPts > SPEECH_CAP_PTS) {
      var speechOverflow = speechPts - SPEECH_CAP_PTS;
      total -= speechOverflow;
      details.push({ id: 'speechCap', label: '话术类证据封顶', points: -speechOverflow,
        matched: true,
        evidence: '官方/安全/正版话术、表情符号等纯文案特征合计 ' + speechPts +
          ' 分，超出上限部分不计入总分（防单类文案堆分误报）' });
      debug('scorePage 话术封顶：' + speechPts + '→' + SPEECH_CAP_PTS +
        '（抵扣 ' + speechOverflow + '）');
    }

    var categoryCount = Object.keys(matchedCategories).length;
    var strongSignal = hasNoahApi || !!adseoResource;

    // v2.2.0：统计 SDK 与品牌冒充的模板指纹组合改为显式计分项（原强信号直拦）。
    // 银狐冒充站模板特征保留权重但交由分层策略裁决；51.la 单独出现不拦
    // （正规统计服务，误报主源），下载入口限定排除"挂 51.la 的品牌教程博客"
    add('templateFingerprint', '统计 SDK 与品牌冒充模板指纹组合', 40,
      hasSdk && !!brandMatch && downloadLinks.length >= 1,
      hasSdk && brandMatch && downloadLinks.length >= 1 ?
        brandMatch.name + ' + 51.la SDK + ' + downloadLinks.length + ' 个下载入口' : '',
      'structure');

    // 返回完整评分结果：总分/阈值/明细/品牌信息/正版官网地址/官方标识。
    // v2.1.2 新增字段：categories（命中类别数，供后台多样性裁决）、
    // strongSignal（强特征标记，供后台豁免多样性约束直接硬拦）；
    // v2.1.3 新增：categoriesList（命中类别名数组，供后台异步增强时
    // 判断新增指标是否引入了新证据类别）、icpClaimed（页面是否声明备案，
    // 供后台 ICP API 核验伪造备案）
    return {
      total: total, threshold: 150, details: details, url: location.href, title: document.title,
      categories: categoryCount, categoriesList: Object.keys(matchedCategories),
      strongSignal: strongSignal,
      icpClaimed: icpClaimed,
      // v2.3.0：可信 AI 对话页标记——后台据此跳过品牌补检与 ICP API 核验，
      // 并激活外链核查通道（见 background scanAiChatLinks）
      aiChatPage: isAiChatPage,
      // v2.4.0：UGC 平台标记——后台 enhanceScoreAsync 据此跳过 ICP API 核验
      ugcPage: isUgcPage,
      // v2.5.0：安全研究论坛标记——同列 ICP 豁免；前台另注入提示卡片
      // 并拦截未加白状态的站外链接（见文件末尾安全论坛模块）
      secForum: isSecForumPage,
      // v2.6.0：连字符模式域名命中标记——后台异步反查 ICP 备案做信任校平
      // （持有有效备案 -20 / 明确查无 +8，见 background enhanceScoreAsync）
      patternDomainHit: !!patternDomain,
      // v2.2.0：页面声明的合规备案号原文——供后台与 API 备案记录做
      // 一致性比对（一致 -80 / 不符 +30，见 enhanceScoreAsync 三态核验）
      icpNumber: icpLinkedMatch || icpTextMatch || '',
      brand: brandMatch ? brandMatch.name : '',
      officialUrl: brandMatch && brandMatch.officialUrls && brandMatch.officialUrls[0] || '',
      officialBadge: officialBadge
    };
  }

  // 执行一次评分并上报（结果与上次相同时跳过，避免消息风暴）
  function evaluate() {
    timer = null;
    // 隐藏页跳过评分（v2.1.0 稳定性修复）：
    // 1) 性能——预渲染/后台标签无需消耗 CPU 跑 30 项指标评分
    //    （评分含全量 DOM 查询与性能条目遍历，开销不小）
    // 2) 时机——页面可见时 DOM/懒加载资源更完整，评分结论更准
    // 页面转为可见时由 visibilitychange 重新调度补评，不会漏报
    if (document.hidden) {
      debug('content.js 跳过评分：页面不可见，待可见后补评');
      document.addEventListener('visibilitychange', function onVis() {
        if (document.hidden) return;
        document.removeEventListener('visibilitychange', onVis);
        scheduleEvaluate();
      });
      return;
    }
    var result = scorePage();
    // 防重指纹含官方标识状态：标识被延迟插入 DOM 时（页脚后加载）
    // 确保重新上报，让后台的豁免决策拿到最新标识状态
    var reportKey = result.total + ':' + result.officialBadge + ':' +
      result.details.map(function(item) { return item.matched ? '1' : '0'; }).join('');
    if (reportKey === lastReportKey) return;
    lastReportKey = reportKey;
    try {
      // 回执处理：
      // v2.1.0：blocked+exempt=official 表示"触发评分阈值但因官方标识放行"
      //        ——注入悬浮验证卡片交由用户自行核验
      // v2.1.2：blocked=false+warn=true 表示"软拦截层"（评分 100~149）——
      //        不跳警告页，注入顶部黄色警示横幅，浏览不中断
      // v2.1.3：warn=true 同时冻结页面（脚本+链接停用，用户验证后解冻）；
      //        notice=true 表示"低权重提示层"（评分 80~99）——灰蓝细横幅
      chrome.runtime.sendMessage({ action: 'scorePage', result: result }, function(response) {
        void chrome.runtime.lastError;
        if (!response) return;
        if (response.blocked && response.exempt === 'official') {
          injectVerifyCard('score');
          recordAppliedUi('blocked', false, result.total);
          return;
        }
        if (response.blocked) return; // 硬拦截跳转中，页面 UI 无需调整
        // v2.2.4：同步回执统一走 applyScoreVerdict——与异步对账共用同一套
        // 层级切换逻辑。DOM 重评使拦截方式变化时（如动态挂载的特征把 70 分
        // 推上 85/120 跨层级），自动清除旧层级残留 UI；v2.2.5 起 Toast 仅在
        // 拦截方式（UI 层级）实际切换时弹出并带 15 秒防抖冷却，同方式内的
        // 分数波动静默处理；首次应用静默，与初始拦截/放行流程的历史行为一致。
        // effectiveTotal = 后台实际用于判定的总分（可能已被增强终局结论
        // 替换），用它记录状态才能与异步对账的状态比较保持一致
        var effTotal = (response.effectiveTotal != null) ?
          Number(response.effectiveTotal) : result.total;
        applyScoreVerdict({
          level: response.warn ? 'warn' : (response.notice ? 'notice' :
            (response.card ? 'card' : 'none')),
          total: effTotal,
          card: !!response.card,
          details: result.details,
          categoriesList: result.categoriesList,
          // 回执带 unfrozen = 解冻窗口期内：仅警示不冻结（v2.1.3 r3）
          freeze: !response.unfrozen
        }, true);
      });
    } catch(e) { /* 扩展上下文失效时静默 */ }
  }

  // 防抖调度：DOM/资源高频变化时合并为一次评分
  function scheduleEvaluate() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(evaluate, 150);
  }

  // 判断 href 是否为占位符（# / javascript:void(0)）
  function isPlaceholderHref(value) {
    value = String(value || '').trim().toLowerCase().replace(/;$/, '');
    return value === '#' || value === 'javascript:void(0)' || value === 'javascript:void(0)';
  }

  // DOM 变化监听：捕获下载链接被运行时改写（占位 → 真实地址），
  // 并在任何 DOM 变化后重新调度评分
  var observer = new MutationObserver(function(records) {
    // DOM 已变化：官方标识结论作废（标识可能刚被插入或移除），
    // 下次评分时重算（v2.1.1 缓存失效点）
    officialBadgeCache = null;
    records.forEach(function(record) {
      if (record.type !== 'attributes' || record.attributeName !== 'href') return;
      var el = record.target;
      var current = el.getAttribute('href') || '';
      var text = String(el.innerText || el.textContent || '');
      if (isPlaceholderHref(record.oldValue) && !isPlaceholderHref(current) &&
          /下载|download/i.test(text)) {
        changedDownloadLinks.add(el);
      }
    });
    scheduleEvaluate();
    // v2.3.0：AI 对话页外链扫描联动（非 AI 页面为空操作，见文件尾部模块）
    scheduleLinkScan();
  });

  observer.observe(document, {
    subtree: true, childList: true, characterData: true,
    attributes: true, attributeFilter: ['href', 'src'], attributeOldValue: true
  });

  // 资源加载监听：懒加载的脚本/图片就绪后重新评分（buffered 补齐已加载条目）
  try {
    var resourceObserver = new PerformanceObserver(scheduleEvaluate);
    resourceObserver.observe({ type: 'resource', buffered: true });
  } catch(e) { /* 旧浏览器退化为 DOM/load 事件触发 */ }

  // popup 主动查询当前页评分（"重新评分"按钮/打开弹窗时调用）
  chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
    // v2.2.4：异步增强把结论推上硬拦截线——后台跳转警告页前先通知本页面
    // 弹"已达拦截标准"升级 Toast（停留约 1.6 秒后跳转）
    if (msg.action === 'scoreEscalated') {
      injectScoreChangeToast({
        direction: 'up',
        level: 'blocked',
        total: Number(msg.total) || 0
      });
      sendResponse({ ok: true });
      return;
    }
    // v2.2.2：后台异步增强后 UI 层级与同步结论不一致 → 升降级对账
    //（备案核验一致 -80、老域名抵扣 -15 等负分回撤；新注册域名/盗用备案等
    // 正分升级——无论方向均调整 UI 并弹 Toast）
    if (msg.action === 'scoreAdjusted') {
      handleScoreAdjusted(msg);
      sendResponse({ ok: true });
      return;
    }
    if (msg.action === 'getPageScore') {
      brandConfigReady.then(function() { sendResponse(scorePage()); });
      return true;
    }
    // v2.3.4：AI 外链核查第二阶段——ICP 备案核验完成后的终局结论推送，
    // 据注册表找回原锚点，原位把"ICP核验中"动画替换为最终徽标
    if (msg.action === 'aiLinkVerdict' && msg.url) {
      const anchorEl = aiChatAnchorByUrl && aiChatAnchorByUrl.get(msg.url);
      if (anchorEl && anchorEl.isConnected) injectLinkBadge(anchorEl, msg.verdict || {});
      sendResponse({ ok: true });
      return;
    }
  });

  // 品牌库就绪后开始首轮评分（DOM 加载完成或已加载完成）
  brandConfigReady.then(function() {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scheduleEvaluate, { once: true });
    else scheduleEvaluate();
  });
  // load 事件兜底：确保首屏评分一定会执行
  window.addEventListener('load', scheduleEvaluate, { once: true });

  // ===== v2.3.0：AI 对话页外链风险标注 =====
  // v2.4.0 起同时覆盖 UGC 平台（bilibili/weibo 等）顶层框架。
  // AI 对话中的链接是 AIGC 输出（幻觉域名/仿冒站）；UGC 平台的评论区·
  // 简介·动态外链是用户投放——评论区正是银狐投毒的主渠道（伪装破解/
  // 补丁/网盘链接），核查同样必要甚至更重要。对每条跨站外链请求后台
  // 核查（黑名单/白名单/可疑模式），可疑模式域名再由后台以"沙箱防追踪"
  // 方式探测（无 Cookie、无 Referer、不读响应体、8 秒超时），
  // 结果以微型徽标标注在链接旁；平台自营短链域（t.cn/b23.tv 等）
  // 探测时跟随重定向核对最终落地域，短链跳转钓鱼即在此环节现形。
  // 体验约束：16px 高内联徽标不改变布局流；safe/unknown 仅显示色点；
  // 不拦截点击、不修改链接本身；流式输出增量渲染时经 WeakMap 去重，
  // 只处理新增/地址变更的锚点。
  // scheduleLinkScan 由上方 MutationObserver 回调调用（函数声明提升，先调后定义安全）
  var aiChatActive = (window.top === window) &&
    (isAiChatHostname(location.hostname) || isUgcHostname(location.hostname));
  var linkScanTimer = null;
  var processedAnchors = typeof WeakMap !== 'undefined' ? new WeakMap() : null;
  // v2.3.4：url → 锚点注册表——后台 ICP 核验完成后经 aiLinkVerdict 消息
  // 推送终局结论，据此找到原锚点原位刷新徽标（超容量整体清空防泄漏）
  var aiChatAnchorByUrl = typeof Map !== 'undefined' ? new Map() : null;
  // v2.4.0：UGC 平台评论区外链密度高且是投毒主渠道，单批上限放宽到 30；
  // AI 对话页维持 15
  var LINK_SCAN_MAX_PER_BATCH = isUgcHostname(location.hostname) ? 30 : 15;

  function scheduleLinkScan() {
    if (!aiChatActive || !processedAnchors) return;
    if (linkScanTimer) clearTimeout(linkScanTimer);
    // 流式输出期间 DOM 高频变化，600ms 防抖合并为一次扫描
    linkScanTimer = setTimeout(runLinkScan, 600);
  }

  // 收集本轮待核查锚点：http(s) 跨站外链、未处理过或 href 已变更的
  function collectExternalLinks() {
    var pageHost = location.hostname.toLowerCase();
    var found = [];
    var anchors = document.querySelectorAll('a[href]');
    for (var i = 0; i < anchors.length && found.length < LINK_SCAN_MAX_PER_BATCH; i++) {
      var anchorEl = anchors[i];
      var href = anchorEl.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) continue;      // 相对路径/锚点/js: 协议跳过
      var absUrl;
      try { absUrl = new URL(href, location.href).href; } catch(e) { continue; }
      if (processedAnchors.get(anchorEl) === absUrl) continue; // 已按此地址处理过
      processedAnchors.set(anchorEl, absUrl);
      var targetHost = '';
      try { targetHost = new URL(absUrl).hostname.toLowerCase(); } catch(e) { continue; }
      if (!targetHost) continue;
      if (isSameSiteHost(targetHost, pageHost)) continue;       // 站内链接不标注
      found.push({ anchor: anchorEl, url: absUrl });
    }
    return found;
  }

  function runLinkScan() {
    linkScanTimer = null;
    if (!aiChatActive) return;
    var items = collectExternalLinks();
    if (!items.length) return;
    // 先挂"检测中"占位徽标（蓝点脉冲动画）；疑似仿冒域名后台会转入
    // ICP 备案核验第二阶段，届时回执 pendingIcp 过渡态换"ICP核验中"动画，
    // 终局结论再经 aiLinkVerdict 消息推回原位刷新
    items.forEach(function(item) {
      if (aiChatAnchorByUrl) {
        if (aiChatAnchorByUrl.size > 400) aiChatAnchorByUrl.clear();
        aiChatAnchorByUrl.set(item.url, item.anchor);
      }
      injectLinkBadge(item.anchor, { level: 'pending' });
    });
    try {
      chrome.runtime.sendMessage({
        action: 'scanAiChatLinks',
        urls: items.map(function(item) { return item.url; })
      }, function(response) {
        void chrome.runtime.lastError;
        if (!response || !response.ok || !response.results) {
          // 后台不可用时撤掉占位动画，避免永远转圈
          items.forEach(function(item) {
            injectLinkBadge(item.anchor, { level: 'unknown', reason: '核查服务暂不可用' });
          });
          return;
        }
        items.forEach(function(item) {
          var verdict = response.results[item.url] ||
            { level: 'unknown', reason: '未获得核查结果' };
          injectLinkBadge(item.anchor, verdict);
        });
      });
    } catch(e) { /* 扩展上下文失效时静默 */ }
  }

  // 微型评分卡片：closed Shadow DOM 注入（页面样式无法渗入，
  // 页面也无法读取内部结构伪造）。视觉分级：
  //   pending 蓝点脉冲+"检测中"（沙箱探测中）/ pendingIcp 琥珀点脉冲+
  //   "ICP核验中"（备案核验中）/ danger 红点+"危险" / warn 橙点+"可疑" /
  //   safe 绿点 / unknown 绿系色点——v2.3.5 起不用灰色：
  //   未探测=淡绿、核验完成正常=正绿（灰色观感像"未完成任务"）
  // 悬停或点击徽标均弹出核查详情面板（结论/目标域/探测方式）；
  // 点击已 stopPropagation，不会触发链接跳转或页面自身点击逻辑。
  // v2.3.2：面板宿主挂在 documentElement 下（transform 祖先会把 fixed
  // 定位基准改成容器，导致面板错位到页面角落——详见 injectLinkBadge 内注释）
  var activeBadgePanels = [];   // 打开中的面板 close 函数（滚动时统一收起）
  var badgeScrollHooked = false;
  function hookBadgeScroll() {
    if (badgeScrollHooked) return;
    badgeScrollHooked = true;
    document.addEventListener('scroll', function() {
      activeBadgePanels.forEach(function(close) { close(); });
      if (activeBadgePanels.length > 200) activeBadgePanels.splice(0, 100);
    }, true);
  }

  function injectLinkBadge(anchorEl, verdict) {
    try {
      if (anchorEl.__sfLinkBadge && anchorEl.__sfLinkBadge.parentNode) {
        anchorEl.__sfLinkBadge.parentNode.removeChild(anchorEl.__sfLinkBadge);
      }
      // 同步清理旧详情面板宿主（面板挂在 documentElement 下，见下）
      if (anchorEl.__sfLinkPanel && anchorEl.__sfLinkPanel.parentNode) {
        anchorEl.__sfLinkPanel.parentNode.removeChild(anchorEl.__sfLinkPanel);
      }
      var META = {
        danger:  { color: '#d93025', label: '危险',   cls: 'b danger' },
        warn:    { color: '#e8710a', label: '可疑',   cls: 'b warn' },
        safe:    { color: '#188038', label: '',       cls: 'b plain' },
        unknown: { color: '#9aa0a6', label: '',       cls: 'b plain' },
        pending: { color: '#1a73e8', label: '检测中', cls: 'b pending' },
        // v2.3.4：第二阶段过渡态——沙箱探测已过、正在核验 ICP 备案
        //（琥珀点脉冲，与探测阶段的蓝点区分开）
        pendingIcp: { color: '#f9ab00', label: 'ICP核验中', cls: 'b pending' }
      };
      var m = META[verdict.level] || META.unknown;
      // v2.3.5：unknown 分两档绿色——灰色观感像"任务没做完"，弃用。
      //   未发起沙箱探测（纯静态核查无已知风险）→ 淡绿
      //   探测/ICP 核验完成且正常 → 正绿（全流程核验通过的明确信号）
      if (verdict.level === 'unknown') {
        m = { color: verdict.probed ? '#188038' : '#a5d6a7', label: '', cls: 'b plain' };
      }
      var probeText = verdict.level === 'pending'
        ? '正在后台沙箱探测…'
        : (verdict.probed ? '已沙箱访问（无 Cookie / 无 Referer）' : '未发起网络访问');
      var levelTitle =
        verdict.level === 'pending' || verdict.level === 'pendingIcp' ? '' :
        verdict.level === 'danger' ? '—— 高风险，建议勿访问' :
        verdict.level === 'warn' ? '—— 存在可疑特征' :
        verdict.level === 'safe' ? '—— 可信域名' :
        verdict.level === 'unknown' ?
          (verdict.probed ? '—— 已完成核验，未发现风险' : '—— 静态核查未见风险') : '';

      var hostSpan = document.createElement('span');
      hostSpan.className = 'sf-link-badge-host';
      hostSpan.setAttribute('role', 'note');
      hostSpan.setAttribute('aria-label', '链接风险核查：' + (verdict.reason || '核查中'));
      var shadow = hostSpan.attachShadow({ mode: 'closed' });

      var style = document.createElement('style');
      style.textContent =
        ':host{all:initial}' +
        '.b{display:inline-flex;align-items:center;gap:4px;height:16px;margin-left:5px;' +
        'padding:0 7px;border-radius:8px;vertical-align:middle;white-space:nowrap;' +
        'font:500 11px/16px system-ui,-apple-system,"Segoe UI",sans-serif;' +
        'color:#5f6368;background:#f1f3f4;cursor:pointer;user-select:none}' +
        '.b.plain{padding:0;background:transparent}' +
        '.b.danger{color:#d93025;background:#fce8e6}' +
        '.b.warn{color:#b06000;background:#fef7e0}' +
        '.b.pending{color:#1a73e8;background:#e8f0fe}' +
        '.d{width:7px;height:7px;border-radius:50%;flex:none}' +
        '.b.plain .d{width:10px;height:10px}' +
        '@keyframes sfPulse{0%{opacity:.3}50%{opacity:1}100%{opacity:.3}}' +
        '.b.pending .d{animation:sfPulse 1s ease-in-out infinite}';
      shadow.appendChild(style);

      var badge = document.createElement('span');
      badge.className = m.cls;
      badge.setAttribute('role', 'button');
      badge.setAttribute('aria-label', '查看链接核查详情');
      var dot = document.createElement('span');
      dot.className = 'd';
      dot.style.background = m.color;
      badge.appendChild(dot);
      if (m.label) {
        var txt = document.createElement('span');
        txt.textContent = m.label;  // textContent 防注入（reason/host 不进 HTML）
        badge.appendChild(txt);
      }
      shadow.appendChild(badge);

      // 详情面板：悬停 / 点击均可呼出。面板不放在徽标的 shadow 里，而是
      // 挂在 document.documentElement 直下的独立宿主——AI 对话页消息容器
      // 普遍带 transform 动画，CSS 规范下 transform 祖先会把 position:fixed
      // 的定位基准从视口改成该容器（此前面板"跑页面右上角"的根因）。
      // 文档根节点无 transform 祖先，fixed 恒以视口定位
      var panelHost = document.createElement('span');
      panelHost.className = 'sf-link-panel-host';
      var pshadow = panelHost.attachShadow({ mode: 'closed' });
      var pstyle = document.createElement('style');
      pstyle.textContent =
        ':host{all:initial;position:fixed;left:0;top:0;z-index:2147483647;display:none}' +
        '.panel{max-width:300px;padding:10px 12px;border-radius:8px;background:#fff;' +
        'color:#202124;font:400 12px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif;' +
        'box-shadow:0 4px 16px rgba(0,0,0,.2);border:1px solid #dadce0}' +
        '.panel .t{font-weight:600;margin-bottom:4px}' +
        '.panel .row{display:flex;gap:6px;margin-top:2px}' +
        '.panel .k{color:#5f6368;flex:none}';
      pshadow.appendChild(pstyle);

      var panel = document.createElement('div');
      panel.className = 'panel';
      var title = document.createElement('div');
      title.className = 't';
      title.textContent = '银狐拦截系统 · 链接核查' + levelTitle;
      panel.appendChild(title);
      [['结论', verdict.reason || (verdict.level === 'pending' ? '正在核查…' : '未发现已知风险')],
       ['目标', verdict.host || ''],
       ['探测', probeText]].forEach(function(pair) {
        if (!pair[1]) return;
        var row = document.createElement('div');
        row.className = 'row';
        var k = document.createElement('span'); k.className = 'k'; k.textContent = pair[0];
        var v = document.createElement('span'); v.textContent = pair[1];
        row.appendChild(k); row.appendChild(v); panel.appendChild(row);
      });
      pshadow.appendChild(panel);
      try { (document.documentElement || document.body).appendChild(panelHost); } catch(e2) { /* */ }

      var isOpen = false;
      function positionPanel() {
        // getBoundingClientRect 返回视口坐标，与 fixed 基准一致
        var r = badge.getBoundingClientRect();
        if (!r.width && !r.height && !r.top && !r.left) return;  // 徽标已不在文档中
        var vw = window.innerWidth || 800;
        var vh = window.innerHeight || 600;
        panelHost.style.left = Math.max(4, Math.min(r.left, vw - 310)) + 'px';
        // 视口下方放不下时翻转到徽标上方（估算面板高度 ~150px）
        if (r.bottom + 156 > vh && r.top > 160) {
          panelHost.style.top = '';
          panelHost.style.bottom = (vh - r.top + 6) + 'px';
        } else {
          panelHost.style.bottom = '';
          panelHost.style.top = (r.bottom + 6) + 'px';
        }
      }
      function openPanel() { positionPanel(); panelHost.style.display = 'block'; isOpen = true; }
      function closePanel() { panelHost.style.display = 'none'; isOpen = false; }
      badge.addEventListener('mouseenter', openPanel);
      badge.addEventListener('mouseleave', closePanel);
      badge.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        if (isOpen) closePanel(); else openPanel();
      });
      hookBadgeScroll();
      activeBadgePanels.push(closePanel);

      anchorEl.parentNode.insertBefore(hostSpan, anchorEl.nextSibling);
      anchorEl.__sfLinkBadge = hostSpan;
      anchorEl.__sfLinkPanel = panelHost;
    } catch(e) { /* 极端 DOM 状态下静默 */ }
  }

  // 初始扫描兜底：load 后延迟一次（等首批对话内容渲染完成）；
  // 后续增量内容由 MutationObserver → scheduleLinkScan 驱动
  if (aiChatActive) setTimeout(runLinkScan, 1200);

  // ===== v2.5.0：安全研究论坛提示卡片与站外链接防护 =====
  var secForumActive = (window.top === window) && isSecurityForumHostname(location.hostname);
  if (secForumActive) {
    var SEC_FORUM_REG = getRegistrableDomain(location.hostname) || location.hostname;
    var secForumWhitelisted = false;
    var secForumBannerHost = null;

    // 与 popup/warning 页同一协议：规范化去重后写 storage.local 的 whitelist 键，
    // background 的 storage.onChanged 监听器自动同步缓存与 DNR allow 规则
    function secForumAddWhitelist(done) {
      try {
        chrome.storage.local.get('whitelist', function(stored) {
          var wl = ((stored && stored.whitelist) || []).map(function(d) {
            return String(d || '').toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
          }).filter(function(d, i, a) { return d && a.indexOf(d) === i; });
          if (wl.indexOf(SEC_FORUM_REG) === -1) wl.push(SEC_FORUM_REG);
          chrome.storage.local.set({ whitelist: wl }, function() {
            if (chrome.runtime.lastError) { done(false); return; }
            secForumWhitelisted = true;
            removeSecForumBanner();
            done(true);
          });
        });
      } catch(e) { done(false); }
    }

    function removeSecForumBanner() {
      if (secForumBannerHost && secForumBannerHost.parentNode) {
        secForumBannerHost.parentNode.removeChild(secForumBannerHost);
      }
      secForumBannerHost = null;
    }

    function ackSecForumNotice() {
      try { window.sessionStorage.setItem('yhSecForumAck', SEC_FORUM_REG); } catch(e) { /* */ }
      removeSecForumBanner();
    }

    // ---- 顶部提示卡片（closed Shadow DOM，与验证卡片/横幅同一实现约定）----
    function injectSecForumNotice() {
      if (secForumBannerHost || !document.documentElement) return;
      var host = document.createElement('div');
      // 注意：宿主上的内联 all:initial 会把 position 重置为 static 并覆盖 shadow
      // 内的 :host{position:fixed}（内联样式优先级更高），因此定位必须在内联里重申，
      // 否则卡片会掉到文档流末尾、被页面内容压在底下（v2.5.2 之前的错位即此因）
      host.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;' +
        'z-index:2147483646;display:flex;justify-content:center;pointer-events:none;';
      try { var sh = host.attachShadow({ mode: 'closed' }); } catch(e) { return; }
      sh.innerHTML =
        '<style>' +
        ':host { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483646;' +
        '  display: flex; justify-content: center; pointer-events: none;' +
        '  font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
        '.card { pointer-events: auto; margin-top: 10px; max-width: 680px; width: calc(100% - 24px);' +
        '  box-sizing: border-box; background: rgba(255,255,255,0.97);' +
        '  border: 1px solid #e2e8f0; border-radius: 14px; padding: 14px 16px 12px;' +
        '  box-shadow: 0 12px 40px rgba(2,6,23,0.18), 0 2px 8px rgba(2,6,23,0.06);' +
        '  animation: rise .3s ease both; }' +
        '@keyframes rise { from { opacity: 0; transform: translateY(12px); }' +
        '  to { opacity: 1; transform: none; } }' +
        '.head { display: flex; align-items: center; gap: 8px; }' +
        '.head svg { flex-shrink: 0; color: #d97706; }' +
        '.title { font-size: 13.5px; font-weight: 700; color: #1e293b; flex: 1; }' +
        '.close { border: none; background: none; cursor: pointer; padding: 2px; display: flex;' +
        '  color: #94a3b8; border-radius: 6px; }' +
        '.close:hover { color: #475569; background: #f1f5f9; }' +
        '.rule { display: inline-block; margin-top: 8px; font-size: 11px; font-weight: 700;' +
        '  color: #b45309; background: #fef3c7; padding: 2.5px 9px; border-radius: 20px; }' +
        '.desc { font-size: 12px; color: #64748b; line-height: 1.65; margin: 8px 0 10px; }' +
        '.desc b { color: #b91c1c; font-weight: 700; }' +
        '.ops { display: flex; flex-direction: column; gap: 6px; }' +
        '.main-btn { display: flex; align-items: center; justify-content: center; gap: 7px;' +
        '  width: 100%; box-sizing: border-box; cursor: pointer; font-size: 12.5px; font-weight: 600;' +
        '  color: #1d4ed8; background: #f8faff; border: 1px solid #dbeafe; border-radius: 8px;' +
        '  padding: 7px 10px; transition: background .15s, border-color .15s; }' +
        '.main-btn:hover { background: #dbeafe; border-color: #93c5fd; }' +
        '.wl-btn { display: flex; align-items: center; justify-content: center; gap: 7px;' +
        '  width: 100%; box-sizing: border-box; cursor: pointer; font-size: 12px; font-weight: 600;' +
        '  color: #64748b; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;' +
        '  padding: 7px 10px; transition: background .15s, color .15s, border-color .15s; }' +
        '.wl-btn:hover { background: #f1f5f9; color: #475569; }' +
        '.wl-btn.arm { color: #b45309; background: #fef3c7; border-color: #fcd34d; font-weight: 700; }' +
        '.wl-btn.done { color: #059669; background: #ecfdf5; border-color: #a7f3d0; }' +
        '.wl-btn.fail { color: #b91c1c; background: #fef2f2; border-color: #fecaca; }' +
        '.wl-btn:disabled { cursor: default; opacity: .85; }' +
        '</style>' +
        '<div class="card" role="alertdialog" aria-label="安全论坛提示">' +
        '  <div class="head">' +
        '    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
        '    <span class="title">这里是安全技术研究论坛</span>' +
        '    <button class="close" title="本次会话不再提示" aria-label="关闭提示">' +
        '      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
        '    </button>' +
        '  </div>' +
        '  <span class="rule">安全研究社区：' + SEC_FORUM_REG + '</span>' +
        '  <div class="desc">论坛帖子中的附件、工具、"破解软件"、样本可能包含<b>真实木马与恶意程序</b>' +
        '（包括银狐木马——常借"远控工具/破解补丁/游戏外挂"名义传播），仅供安全研究人员在隔离环境中分析。' +
        '请勿下载运行任何附件，不要随意点击站外链接——除非你确切知道自己在做什么。</div>' +
        '  <div class="ops">' +
        '    <button class="main-btn" type="button">' +
        '      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>' +
        '      我知道了（本次会话不再提示）</button>' +
        '    <button class="wl-btn" type="button">' +
        '      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>' +
        '      永久信任此论坛（同时关闭站外链接拦截）</button>' +
        '  </div>' +
        '</div>';
      var wlBtn = sh.querySelector('.wl-btn');
      var WL_DEFAULT_TEXT = '永久信任此论坛（同时关闭站外链接拦截）';
      sh.querySelector('.close').addEventListener('click', ackSecForumNotice);
      sh.querySelector('.main-btn').addEventListener('click', ackSecForumNotice);
      // 两段式确认：与验证卡片加白按钮同一交互——首击进入琥珀警示态，
      // 5 秒内再点才执行写白名单，防小白误触把保护永久关掉
      wlBtn.addEventListener('click', function() {
        if (!wlBtn.dataset.armed) {
          wlBtn.dataset.armed = '1';
          wlBtn.classList.add('arm');
          wlBtn.textContent = '再次点击确认永久信任';
          setTimeout(function() {
            if (wlBtn.dataset.armed && !wlBtn.disabled) {
              delete wlBtn.dataset.armed;
              wlBtn.classList.remove('arm');
              wlBtn.textContent = WL_DEFAULT_TEXT;
            }
          }, 5000);
          return;
        }
        wlBtn.disabled = true;
        wlBtn.textContent = '添加中…';
        secForumAddWhitelist(function(ok) {
          if (ok) {
            wlBtn.textContent = '已加入白名单';
            wlBtn.classList.remove('arm');
            wlBtn.classList.add('done');
            setTimeout(removeSecForumBanner, 1500);
          } else {
            delete wlBtn.dataset.armed;
            wlBtn.classList.remove('arm');
            wlBtn.classList.add('fail');
            wlBtn.textContent = '加入白名单失败，请重试';
            wlBtn.disabled = false;
          }
        });
      });
      document.documentElement.appendChild(host);
      secForumBannerHost = host;
    }

    // ---- 站外链接拦截弹窗（未加白时）----
    var secModalHost = null;
    function closeSecForumModal(navigateUrl, newTab) {
      if (!secModalHost) return;
      if (secModalHost._parent && secModalHost._parentNode) {
        secModalHost._parentNode.removeChild(secModalHost);
      }
      secModalHost = null;
      if (navigateUrl) {
        if (newTab) window.open(navigateUrl, '_blank', 'noopener');
        else location.href = navigateUrl;
      }
    }

    function showSecForumLeaveModal(url, newTab) {
      closeSecForumModal(null);
      if (!document.documentElement) return;
      var targetHost = '';
      try { targetHost = new URL(url).hostname; } catch(e) { /* */ }
      var host = document.createElement('div');
      host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;';
      try { var sh = host.attachShadow({ mode: 'closed' }); } catch(e) { return; }
      sh.innerHTML =
        '<style>' +
        ':host { position: fixed; inset: 0; z-index: 2147483647;' +
        '  font-family: system-ui, "Microsoft YaHei", sans-serif; }' +
        '.ov { position: absolute; inset: 0; background: rgba(15,23,42,.45);' +
        '  display: flex; align-items: center; justify-content: center; padding: 16px; }' +
        '.box { background: rgba(255,255,255,0.98); max-width: 480px; width: 100%;' +
        '  box-sizing: border-box; border-radius: 14px; padding: 18px 20px 14px;' +
        '  border: 1px solid #e2e8f0; box-shadow: 0 12px 40px rgba(2,6,23,0.25);' +
        '  animation: rise .25s ease both; }' +
        '@keyframes rise { from { opacity: 0; transform: translateY(12px) }' +
        '  to { opacity: 1; transform: none } }' +
        '.head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }' +
        '.head svg { flex-shrink: 0; color: #dc2626; }' +
        '.title { font-size: 13.5px; font-weight: 700; color: #1e293b; flex: 1; }' +
        '.url { word-break: break-all; background: #f8fafc; border: 1px solid #e2e8f0;' +
        '  border-radius: 8px; padding: 7px 10px; color: #1d4ed8; margin: 8px 0; font-size: 12px; }' +
        '.desc { font-size: 12px; color: #64748b; line-height: 1.65; }' +
        '.desc b { color: #b91c1c; font-weight: 700; }' +
        '.ops { display: flex; flex-direction: column; gap: 6px; margin-top: 12px; }' +
        '.once { display: flex; align-items: center; justify-content: center; gap: 7px;' +
        '  width: 100%; box-sizing: border-box; cursor: pointer; font-size: 12.5px; font-weight: 600;' +
        '  color: #1d4ed8; background: #f8faff; border: 1px solid #dbeafe; border-radius: 8px;' +
        '  padding: 7px 10px; transition: background .15s, border-color .15s; }' +
        '.once:hover { background: #dbeafe; border-color: #93c5fd; }' +
        '.cancel, .forever { display: flex; align-items: center; justify-content: center; gap: 7px;' +
        '  width: 100%; box-sizing: border-box; cursor: pointer; font-size: 12px; font-weight: 600;' +
        '  border-radius: 8px; padding: 7px 10px;' +
        '  transition: background .15s, color .15s, border-color .15s; }' +
        '.cancel { color: #64748b; background: #f8fafc; border: 1px solid #e2e8f0; }' +
        '.cancel:hover { background: #f1f5f9; color: #475569; }' +
        '.forever { color: #64748b; background: #f8fafc; border: 1px solid #e2e8f0; }' +
        '.forever:hover { background: #f1f5f9; color: #475569; }' +
        '.forever.arm { color: #b45309; background: #fef3c7; border-color: #fcd34d; font-weight: 700; }' +
        '.forever.done { color: #059669; background: #ecfdf5; border-color: #a7f3d0; }' +
        '.forever.fail { color: #b91c1c; background: #fef2f2; border-color: #fecaca; }' +
        '</style>' +
        '<div class="ov"><div class="box" role="dialog" aria-modal="true">' +
        '  <div class="head">' +
        '    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>' +
        '    <span class="title">你正在从安全论坛离开，前往外部网站</span>' +
        '  </div>' +
        '  <div class="desc">目标地址：</div>' +
        '  <div class="url"></div>' +
        '  <div class="desc">站外链接可能指向<b>木马、钓鱼或仿冒页面</b>——帖内分享的样本、工具与外链均由坛友自行发布，安全性无法逐一验证。下载文件请优先使用站内附件并核对哈希值。</div>' +
        '  <div class="ops">' +
        '    <button class="once" type="button">仅本次允许访问</button>' +
        '    <button class="cancel" type="button">取消</button>' +
        '    <button class="forever" type="button">永久信任此论坛（关闭链接拦截）</button>' +
        '  </div>' +
        '</div></div>';
      sh.querySelector('.url').textContent = url + (targetHost ? '　（域名：' + targetHost + '）' : '');
      sh.querySelector('.cancel').addEventListener('click', function() { closeSecForumModal(null); });
      sh.querySelector('.once').addEventListener('click', function() { closeSecForumModal(url, newTab); });
      // 两段式确认：与验证卡片/提示卡片的加白按钮同一交互
      var fBtn = sh.querySelector('.forever');
      var F_DEFAULT_TEXT = '永久信任此论坛（关闭链接拦截）';
      fBtn.addEventListener('click', function() {
        if (!fBtn.dataset.armed) {
          fBtn.dataset.armed = '1';
          fBtn.classList.add('arm');
          fBtn.textContent = '再次点击确认永久信任';
          setTimeout(function() {
            if (fBtn.dataset.armed && !fBtn.disabled) {
              delete fBtn.dataset.armed;
              fBtn.classList.remove('arm');
              fBtn.textContent = F_DEFAULT_TEXT;
            }
          }, 5000);
          return;
        }
        fBtn.disabled = true;
        fBtn.textContent = '添加中…';
        secForumAddWhitelist(function(ok) {
          if (ok) {
            fBtn.textContent = '已加入白名单';
            fBtn.classList.remove('arm');
            fBtn.classList.add('done');
            setTimeout(function() { closeSecForumModal(null); }, 1200);
          } else {
            delete fBtn.dataset.armed;
            fBtn.classList.remove('arm');
            fBtn.classList.add('fail');
            fBtn.textContent = '加入白名单失败，请重试';
            fBtn.disabled = false;
          }
        });
      });
      document.documentElement.appendChild(host);
      secModalHost = host;
      secModalHost._parent = true;
      secModalHost._parentNode = document.documentElement;
    }

    // 跨站外链判定：http(s) 且注册域不同于当前注册域
    function secForumExternalHref(anchorEl) {
      var href = anchorEl.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) return null;
      var u = null;
      try { u = new URL(href, location.href); } catch(e) { return null; }
      var reg = getRegistrableDomain(u.hostname.toLowerCase());
      if (!reg || reg === SEC_FORUM_REG) return null;
      return u.href;
    }

    function secForumClickGuard(e) {
      if (secForumWhitelisted) return;
      // click 只处理主键；auxclick 处理中键（新标签打开）
      if (e.type === 'click' && e.button !== 0) return;
      if (e.type === 'auxclick' && e.button !== 1) return;
      var el = e.target;
      while (el && el !== document && el.tagName !== 'A') el = el.parentElement;
      if (!el || el === document) return;
      var url = secForumExternalHref(el);
      if (!url) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      showSecForumLeaveModal(url, el.target === '_blank' || e.type === 'auxclick');
    }
    document.addEventListener('click', secForumClickGuard, true);
    document.addEventListener('auxclick', secForumClickGuard, true);

    // 初始化：查白名单决定是否注入提示卡与启用拦截
    try {
      chrome.storage.local.get('whitelist', function(stored) {
        var wl = ((stored && stored.whitelist) || []).map(function(d) {
          return String(d || '').toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
        });
        secForumWhitelisted = wl.some(function(entry) {
          return entry && (
            entry === SEC_FORUM_REG ||
            location.hostname === entry ||
            location.hostname.endsWith('.' + entry));
        });
        // 「我知道了」的会话确认：本标签页会话内不再弹卡（sessionStorage
        // 随标签页关闭自动清除，下次会话恢复提示）
        var sessionAcked = false;
        try { sessionAcked = window.sessionStorage.getItem('yhSecForumAck') === SEC_FORUM_REG; } catch(e) { /* */ }
        if (!secForumWhitelisted && !sessionAcked) {
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', injectSecForumNotice, { once: true });
          } else {
            injectSecForumNotice();
          }
        }
        debug('content.js 安全论坛防护就绪 whitelisted=' + secForumWhitelisted +
          ' sessionAcked=' + sessionAcked);
      });
    } catch(e) { /* 扩展上下文失效 */ }
  }
})();
