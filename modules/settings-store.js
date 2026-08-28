// ============================================================
// 银狐拦截系统 - 设置存储模块（v2.8.0）
// ============================================================
// 职责：设置项的单一事实来源——默认值与规范化。设置持久化在
//       chrome.storage.local 的 `settings` 键（与 popup 的 enabled 开关、
//       设置面板共用同一份）。
// 加载：background.js importScripts（modules/core.js 之后）
// 导出：__YH_SETTINGS__ = { DEFAULTS, normalizeSettings }
// 说明：新开关的"实际生效实现"逐个接线到对应模块后，可随时将
//       QUIRK 标记从 'stub'（仅存储/展示）改为 'wired'；默认关闭，
//       不影响扩展现有拦截行为。
(function(global) {
  'use strict';

  // 设置项默认值与描述（新增项在此追加二元组即可）
  const FIELD_DEFS = [
    // key          默认    说明（面板展示文案在 options/options.js 维护）
    ['enabled',             true,  '扩展总开关（拦截检测）'],
    ['downloadBlock',       false, '可执行/脚本文件下载保护'],
    ['scriptBlock',         false, '恶意脚本/子框架 DNR 拦截'],
    ['locationBlocker',     false, '禁用浏览器定位 API（navigator.geolocation）'],
    ['fingerprintBlocker',  false, '减弱指纹采集（canvas/WebGL/AudioContext，实验）'],
    ['notifyOnBlock',       false, '拦截时弹系统通知']
  ];
  const DEFAULTS = {};
  FIELD_DEFS.forEach(function(f) { DEFAULTS[f[0]] = f[1]; });

  // 是否需要额外权限方可"实际生效"（downloads → downloadBlock/notifyOnBlock）；
  // 现均未接线真拦截（stub），仅持久化与展示
  const PERMISSION_GATED = [
    ['downloadBlock', ['downloads']],
    ['notifyOnBlock', ['notifications']]
  ];

  // 规范化传入设置：补齐缺失字段、强转布尔、剔除未知键（防污染）
  function normalizeSettings(raw) {
    const out = {};
    FIELD_DEFS.forEach(function(f) { out[f[0]] = (raw && typeof raw[f[0]] === 'boolean') ? raw[f[0]] : f[1]; });
    return out;
  }

  global.__YH_SETTINGS__ = global.__YH_SETTINGS__ || Object.freeze({
    DEFAULTS: Object.freeze(Object.assign({}, DEFAULTS)),
    normalizeSettings: normalizeSettings,
    PERMISSION_GATED: PERMISSION_GATED
  });
})(globalThis);
