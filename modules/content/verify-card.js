// 银狐拦截系统 - 官方标识检测 + 悬浮验证卡片模块（v2.7.1 自 content.js 抽取）
// 职责：CONAC 党政机关/事业单位标识防伪造检测（主通道严格校验 bszs.conac.cn
//       链接格式与 32 位站点指纹 + 辅助图片域名通道）；pattern/score 豁免
//       场景的右下角悬浮验证卡片（closed Shadow DOM、仅顶级框架、幂等、
//       两段式永久信任确认，写 storage.local whitelist 键）
// 加载：manifest content_scripts 中 modules/core.js 之后、content.js 之前
// 导出：__YH_VERIFY__ = { detectOfficialBadge, injectVerifyCard }
(function(global) {
'use strict';
const { debug } = globalThis.__YH_CORE__;

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


global.__YH_VERIFY__ = global.__YH_VERIFY__ || Object.freeze({
  detectOfficialBadge: detectOfficialBadge,
  injectVerifyCard: injectVerifyCard
});
})(globalThis);
