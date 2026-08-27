// 银狐拦截系统 - 设置面板（v2.8.0）
// 与 background.js 经 chrome.runtime 消息通讯（getSettings / saveSettings），
// 设置存储键为 storage.local 的 `settings`（schema 与 modules/settings-store.js
// 保持一致）。
(function() {
  'use strict';

  const $ = function(sel) { return document.querySelector(sel); };

  // 设置原型（与 background 端 store 默认值一致；enters when absent）
  const META = [
    { key: 'enabled', section: 'general',
      title: '启用拦截', desc: '关闭后扩展停止一切拦截检测（下载保护与 DNR 规则仍生效）。',
      unit: false },
    { key: 'downloadBlock', section: 'download',
      title: '可执行文件下载保护', desc: '从可疑/未受信站点下载可执行与脚本文件（exe/msi/bat/zip 等）时自动取消，并提示原因。仅保留真实文件分发白名单。',
      unit: false },
    { key: 'scriptBlock', section: 'script',
      title: '恶意脚本拦截', desc: '对黑名单站点发出的脚本/子框架请求使用 DNR 规则拦截（默认关闭，开启可防投毒脚本注入）。',
      unit: false },
    { key: 'locationBlocker', section: 'privacy',
      title: '禁用浏览器定位 API', desc: '覆盖 navigator.geolocation，页面无法读取你的定位（接口返回已拒绝）。仅影响定位，不影响 IP 层。',
      unit: false },
    { key: 'fingerprintBlocker', section: 'privacy',
      title: '减弱指纹采集（实验）', desc: '对 canvas / WebGL / AudioContext 指纹接口做轻微扰动（可能影响部分页面渲染，默认关闭）。',
      unit: false },
    { key: 'notifyOnBlock', section: 'general',
      title: '拦截时弹通知', desc: '发生下载/脚本拦截时显示系统通知（需通知权限）。',
      unit: false }
  ];

  let settings = {};

  function sectionHtml(id, title, desc) {
    return '<div class="section-title">' + title + '</div><p class="section-desc">' + desc + '</p>' +
      '<div id="sec-' + id + '"></div>';
  }
  function cardHtml(meta, value) {
    return '<div class="card"><div class="card-title"><span>' + meta.title + '</span>' +
      '<label class="switch"><input type="checkbox" data-key="' + meta.key + '"' +
      (value ? ' checked' : '') + '><span class="slider"></span></label></div>' +
      '<div class="card-desc">' + meta.desc + '</div></div>';
  }

  const SECTIONS = {
    general: { title: '常规', desc: '扩展的整体行为开关。',
      keys: ['enabled', 'notifyOnBlock'] },
    download: { title: '下载保护', desc: '拦截潜在的恶意文件下载。',
      keys: ['downloadBlock'] },
    script: { title: '恶意脚本拦截', desc: '阻断来自风险站点的脚本/子框架加载。',
      keys: ['scriptBlock'] },
    privacy: { title: '定位与防追踪', desc: '不基于 IP 的隐私防护（纯前端 API）。',
      keys: ['locationBlocker', 'fingerprintBlocker'] },
    about: { title: '关于', desc: '版本信息。',
      keys: [] }
  };

  function renderSection(key) {
    const s = SECTIONS[key];
    if (!s) return;
    $('#section-container').innerHTML = sectionHtml(key, s.title, s.desc);
    if (s.items.length) {
      const wrap = $('#sec-' + key);
      s.items.forEach(function(k) {
        const meta = META.find(m => m.key === k);
        if (meta) wrap.insertAdjacentHTML('beforeend', cardHtml(meta, !!settings[k]));
      });
      wrap.querySelectorAll('input[type="checkbox"]').forEach(function(inp) {
        inp.addEventListener('change', function() {
          settings[inp.dataset.key] = inp.checked;
          saveSettings().then(function(ok) {
            toast(ok ? '设置已保存' : '设置保存失败', ok ? 'ok' : 'err');
          });
        });
      });
    }
    if (key === 'about') {
      $('#sec-' + key).innerHTML =
        '<div class="card"><div class="card-title">银狐拦截系统</div>' +
        '<div class="card-desc">检测与拦截银狐木马相关的钓鱼 / 仿冒网站。' +
        '设置面板基础框架先行，更多可配置项将在后续版本逐步开放。</div>' +
        '<div class="card-foot">版本：' + (chrome.runtime.getManifest().version || '') +
        '　作者：Deep_Format / EchoByte</div></div>';
    }
  }

  function navigate(key) {
    document.querySelectorAll('.nav-item').forEach(function(n) {
      n.classList.toggle('active', n.dataset.section === key);
    });
    renderSection(key);
  }
  document.querySelectorAll('.nav-item').forEach(function(n) {
    n.addEventListener('click', function() { navigate(n.dataset.section); });
  });

  function getSettings() {
    return new Promise(function(resolve) {
      chrome.runtime.sendMessage({ action: 'getSettings' }, function(resp) {
        resolve(resp && resp.settings ? resp.settings : {});
      });
    });
  }
  function saveSettings() {
    return new Promise(function(resolve) {
      chrome.runtime.sendMessage({ action: 'saveSettings', settings: settings }, function(res) {
        resolve(!!(res && res.ok));
      });
    });
  }
  function toast(msg, kind) {
    const el = document.createElement('div');
    el.className = 'toast ' + (kind || '');
    el.textContent = msg;
    $('#toast-container').appendChild(el);
    setTimeout(function() { el.remove(); }, 2400);
  }

  $('#export-btn').addEventListener('click', function() {
    const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'yinhu-settings.json';
    a.click();
    toast('设置已导出');
  });
  $('#reset-btn').addEventListener('click', function() {
    if (!confirm('确认恢复所有设置为默认值？')) return;
    settings = { enabled: true };
    const keys = META.map(m => m.key);
    keys.filter(k => k !== 'enabled').forEach(k => { settings[k] = false; });
    saveSettings().then(function() {
      toast('已恢复默认');
      const active = document.querySelector('.nav-item.active');
      if (active) renderSection(active.dataset.section);
    });
  });

  getSettings().then(function(s) {
    settings = s || {};
    // 补齐缺失字段（匿名 META 默认）
    META.forEach(function(m) {
      if (settings[m.key] === undefined) settings[m.key] = false;
    });
    // enabled 缺省为 true
    if (settings.enabled === undefined) settings.enabled = true;
    navigate('general');
  });
})();