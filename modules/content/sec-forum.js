// 银狐拦截系统 - 安全研究论坛防护模块（v2.7.1 自 content.js 抽取）
// 职责：卡饭/看雪/52pojie/T00ls 等论坛的专属防护——进入即注入顶部提示
//       卡片（我知道了=会话级确认 / 一键加白=两段式确认写 whitelist 键）；
//       未加白时捕获阶段拦截跨站外链点击/中键，弹三选确认窗（取消/
//       仅本次访问/永久信任）
// 加载：manifest content_scripts 末位；自判定激活条件，非论坛页零开销
(function() {
'use strict';
const { debug, isSecurityForumHostname, getRegistrableDomain } = globalThis.__YH_CORE__;

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
