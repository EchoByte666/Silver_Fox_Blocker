// 银狐拦截系统 - AI/UGC 外链风险标注模块（v2.7.1 自 content.js 抽取）
// 职责：可信内容平台（AI 对话/UGC）页面对跨站外链请求后台核查并以微型
//       徽标+详情面板标注（pending/pendingIcp 过渡态动画、五级结论、
//       WeakMap 去重、600ms 防抖、单批上限 AI=15/UGC=30）；接收后台
//       aiLinkVerdict 终局结论推送原位刷新
// 加载：manifest content_scripts 中 content.js 之后（由其 MutationObserver
//       经 __YH_LINK_SCAN__.scheduleLinkScan() 联动）
// 导出：__YH_LINK_SCAN__ = { scheduleLinkScan }
(function() {
'use strict';
const { debug, isAiChatHostname, isUgcHostname, isSameSiteHost } = globalThis.__YH_CORE__;

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


  // v2.3.4：ICP 备案核验完成后的终局结论推送（自 content.js 主 IIFE 迁入）
  try {
    chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
      if (msg.action === 'aiLinkVerdict' && msg.url) {
        const anchorEl = aiChatAnchorByUrl && aiChatAnchorByUrl.get(msg.url);
        if (anchorEl && anchorEl.isConnected) injectLinkBadge(anchorEl, msg.verdict || {});
        sendResponse({ ok: true });
      }
    });
  } catch(e) { /* 扩展上下文失效 */ }

  globalThis.__YH_LINK_SCAN__ = globalThis.__YH_LINK_SCAN__ ||
    Object.freeze({ scheduleLinkScan: scheduleLinkScan });
})();
