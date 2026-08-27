// 银狐拦截系统 - DNR 动态规则模块（v2.7.1 自 background.js 抽取）
// 职责：第一层防护的规则生命周期——黑名单按 50 域名/组分批装为 main_frame
//       重定向规则（上限 5000 条，单条失败降级逐条装），白名单（云+默认+
//       本地）以 priority 3 allow 覆盖，gov.cn 豁免；全量替换语义；
//       storage.onChanged 高频触发经 Promise 链串行化
// 依赖注入：init({ getBlocklist, getAllowedDomains })（background.js 注入）
// 导出：__YH_DNR__ = { init, updateDNR, scheduleDNRUpdate }
(function(global) {
'use strict';
const CORE = global.__YH_CORE__;
const debug = CORE.debug;
const LOG = CORE.LOG;
const isGovCn = CORE.isGovCnHostname;
let Deps = {};
function init(deps) { Deps = deps; }

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

    const domains = Deps.getBlocklist() || [];
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
    const allowedDomains = Deps.getAllowedDomains();
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


global.__YH_DNR__ = global.__YH_DNR__ || Object.freeze({
  init: init,
  updateDNR: updateDNR,
  scheduleDNRUpdate: scheduleDNRUpdate
});
})(globalThis);
