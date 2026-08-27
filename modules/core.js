// ============================================================
// 银狐拦截系统 - 共享核心模块（v2.7.0 模块化，单一事实来源 SSOT）
// ============================================================
// 同时以两种方式加载：
//   1. content script：manifest content_scripts js 数组首位（经典脚本，
//      每个 frame 中先于 content.js 执行）
//   2. service worker：background.js 顶部 importScripts() 首位
// 约束：
//   - 本文件不得使用 import/export 语句（须兼容经典脚本环境）；
//   - 一切导出经 globalThis.__YH_CORE__ 命名空间暴露，消费方解构使用；
//   - 只允许纯函数与静态配置，禁止触碰 chrome.* / DOM（两栖环境）。
// 收益：原先 background.js 与 content.js「两处同步」的域名表、豁免表、
//       纯工具函数全部收敛为一份副本，修改只改此文件。
(function(global) {
  'use strict';

  // ===== 全局配置 =====
  // 日志开关：DEBUG=true 时输出详细日志（SW 日志在 chrome://extensions 查看，
  // 页面日志在普通页面 F12 控制台查看）
  const DEBUG = false;
  const LOG = '[银狐拦截] ';
  // content.js 历史名称（与 LOG 同值，保持两侧行为与文案不变）
  const LOG_PREFIX = LOG;

  // 统一日志封装：替代直接覆盖 console.log 的粗暴做法，
  // warn/error 始终保留输出，便于排查线上问题
  function debug(...args) {
    if (DEBUG) console.log(LOG, ...args);
  }

  // 硬编码高危域名（始终拦截，即使远程规则没包含）
  const HARDCODED_DOMAINS = ['noah-admin.site', 'page-admin.site'];

  // 远程规则源列表（按优先级依次尝试）。
  // 注意：offscreen.js 与 popup.js 中暂仍有相同列表（二期收敛），
  // 本文件为权威源。
  // v2.1.1：移除 http://anti-silverfox.wpidc.top 明文源（外部审查指出：
  // HTTP 链路可被中间人篡改规则内容，注入恶意域名或删除拦截条目；
  // HTTPS 源 + 内置 default_rules.txt 兜底已覆盖其作用，风险收益不成比）
  const RULE_SOURCE_URLS = [
    'https://deepformat.top/yh/fake.txt',
    'https://fyh.johnnyblog.top/fake.txt',
    'https://dfcloud.qzz.io/f/MJTE/fake.txt',
    'https://rvit.top/fake.txt',
    'https://cloud.mcnan.top/fake.txt',
    'https://sysbbs.cn/fake.txt'
  ];

  // 云白名单源（作者维护的误报豁免列表）
  const CLOUD_WHITELIST_URL = 'https://deepformat.top/yh/white.txt';

  // 品牌库远程源（v2.0.0 新增：品牌冒充检测配置）
  const BRAND_SOURCE_URL = 'https://deepformat.top/yh/brands.json';

  // v2.0.0 新增：内置默认白名单（始终豁免拦截的知名大站）。
  // 与用户白名单分开存储：本列表只存在于代码中，不写入 storage，
  // 因此弹窗与警告页展示/管理的白名单始终是用户自己添加的条目
  const DEFAULT_WHITELIST = ['*.qq.com', '*.microsoft.com', '*.apple.com', 'https://lestore.lenovo.com/'];

  // 网络/等待超时时间（毫秒）
  const FETCH_TIMEOUT_MS = 10000;   // 单个规则源请求超时
  const OFFSCREEN_WAIT_MS = 15000;  // 等待 offscreen 写入 storage 的超时

  // ===== 域名匹配工具 =====

  // 规则域名（v2.0.0 扩展）：
  //   - 主域标签含连字符的 *.com.cn、*.hl.cn 及其所有子域名
  //   - 主域标签含连字符的 *.cc 及其所有子域名（银狐新变种常用后缀）
  function matchesPatternDomain(hostname) {
    hostname = (hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    const labels = hostname.split('.');
    // *.com.cn / *.hl.cn 模式：需要至少三级标签（如 xxx-yyy.com.cn）
    if (labels.length >= 3 && labels[labels.length - 1] === 'cn' &&
        (labels[labels.length - 2] === 'com' || labels[labels.length - 2] === 'hl') &&
        labels[labels.length - 3].includes('-')) {
      return true;
    }
    // *.cc 模式（v2.0.0 新增）：两级即可（如 xxx-yyy.cc）
    if (labels.length >= 2 && labels[labels.length - 1] === 'cc' &&
        labels[labels.length - 2].includes('-')) {
      return true;
    }
    return false;
  }

  // 通用域名列表匹配（低频路径：白名单、动态传入的列表）
  function matchesDomainList(hostname, domains) {
    hostname = (hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    return (domains || []).some(function(domain) {
      domain = String(domain || '').toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
      return domain && (hostname === domain || hostname.endsWith('.' + domain));
    });
  }

  // 黑名单命中判断（低频路径完整版，含模式域名规则）
  function matchesBlockedDomain(hostname, domains) {
    hostname = (hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    if (matchesPatternDomain(hostname)) return true;
    return matchesDomainList(hostname, domains);
  }

  // v2.2.1 新增：注册域提取（评分引擎/RDAP/ICP 查询目标共用）。
  // www.huorrong.com.cn → huorrong.com.cn；dl.xxx.com 与 xxx.com 同主域
  function getRegistrableDomain(hostname) {
    const labels = String(hostname || '').toLowerCase().split('.').filter(Boolean);
    if (labels.length <= 2) return labels.join('.');
    const tld = labels[labels.length - 1];
    const second = labels[labels.length - 2];
    const isCnDouble = tld === 'cn' && ['com', 'net', 'org', 'gov', 'edu', 'ac'].includes(second);
    const cut = isCnDouble ? 2 : 1;
    return labels.slice(labels.length > cut ? -cut - 1 : 0).join('.');
  }

  // 两个 hostname 是否属于同一注册域（含相等）；任一为空返回 false
  function isSameSiteHost(targetHost, pageHost) {
    targetHost = String(targetHost || '').toLowerCase();
    pageHost = String(pageHost || '').toLowerCase();
    if (!targetHost || !pageHost) return false;
    return getRegistrableDomain(targetHost) === getRegistrableDomain(pageHost);
  }

  // v2.1.0 新增：判断是否为政府网站域名。
  // 降误报策略之一：政府/机关事业单位官网一律不拦截——
  // 政府域名注册受严格审批管制，被黑产仿冒注册的可能性极低，
  // 拦截收益趋零而误报代价高（用户可能正在办理政务业务）。
  // 适用于全部拦截路径：DNR 规则生成 / 导航拦截 / checkPage /
  // scorePage 评分拦截 / blockPage 资源拦截 / content 首屏本地快筛。
  // v2.1.1：扩展后缀覆盖（外部审查指出豁免范围过窄）——
  //   .gov.hk  香港特区政府（注册同样受审批管制）
  //   .政务.cn  政府机构中文 IDN 域名（工信部批准的政府专用后缀）
  // v2.7.0 统一：原 content.js 首屏快筛版本只认 gov.cn，现采用本超集版本，
  // 两侧语义完全一致（后台本就全路径豁免 gov.hk/政务.cn，行为只是对齐）
  function isGovCnHostname(hostname) {
    hostname = String(hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    return hostname === 'gov.cn' || hostname.endsWith('.gov.cn') ||
      hostname === 'gov.hk' || hostname.endsWith('.gov.hk') ||
      hostname === '政务.cn' || hostname.endsWith('.政务.cn');
  }

  // ===== v2.1.3：编辑距离 ≤1 快速判定（域名仿冒模糊匹配用）=====
  // 经典 Levenshtein DP 的特化版：在首个差异点处穷举插入/删除/替换三种
  // 单步操作，任一能对齐剩余部分即距离 ≤1。覆盖 typosquatting 拼写变体：
  // huorrong（双写 r）/ todesc（替换）/ huorongaq（缺写）等
  function levenshteinWithin1(a, b) {
    if (Math.abs(a.length - b.length) > 1) return false;
    if (a === b) return true;
    // 双指针扫描：跳过公共前缀，定位首个差异点
    let i = 0, j = 0;
    const lenA = a.length, lenB = b.length;
    while (i < lenA && j < lenB && a.charAt(i) === b.charAt(j)) { i++; j++; }
    if (i === lenA && j === lenB) return true;
    // 在差异点穷举三种单步修复：a 删一字符 / b 删一字符 / 替换
    let rest1 = i + 1 < lenA ? a.slice(i + 1) : '';
    let rest2 = j < lenB ? b.slice(j) : '';
    if (rest1 === rest2) return true;
    rest1 = i < lenA ? a.slice(i) : '';
    rest2 = j + 1 < lenB ? b.slice(j + 1) : '';
    if (rest1 === rest2) return true;
    rest1 = i + 1 < lenA ? a.slice(i + 1) : '';
    rest2 = j + 1 < lenB ? b.slice(j + 1) : '';
    return rest1 === rest2;
  }

  // ===== v2.3.9：品牌关键词匹配防子串碰撞 =====
  // 远程品牌库存在短英文词（如 LINE 的 "line"）——"cline.bot"、"online"、
  // "deadline"、"linear" 都包含子串 "line"，裸 indexOf/includes 会把大量无关
  // 站点误判为仿冒（cline.bot 实测被判 LINE 仿冒并进入 ICP 核验落橙）。
  // 短词（<5 字符纯拉丁）只在强边界下采信：
  //   - 域名：注册段整体等于关键词，或按 连字符/下划线/数字 切分后某段
  //     整体等于关键词（line-app.top / line2024.com 命中；cline.bot /
  //     linear.app 不命中）
  //   - 文本：词边界匹配（两侧非 [a-z0-9] 或端点）。必须基于未去空格的
  //     原文判定——规范化文本已剥空白，词边界信息不可恢复
  function isShortLatinKeyword(kw) {
    return kw.length < 5 && /^[a-z0-9]+$/.test(kw);
  }

  function shortKeywordBoundaryHit(kw, rawText) {
    return new RegExp('(^|[^a-z0-9])' + kw + '([^a-z0-9]|$)')
      .test(String(rawText || '').toLowerCase());
  }

  function brandDomainKeywordHit(kw, hostname, registrable) {
    if (String(hostname).indexOf(kw) === -1) return false;
    if (!isShortLatinKeyword(kw)) return true;
    const label = String(registrable || '');
    if (label === kw) return true;
    return label.split(/[-_0-9]/).indexOf(kw) !== -1;
  }

  // ===== v2.1.5：开发者平台豁免表（品牌冒充检测专用）=====
  // 代码托管/技术问答/文档站的页面天然高频提及各软件品牌（README、
  // 评测对比、API 文档），"提及"≠"冒充"。hostname 命中本表（含子域名）
  // 时跳过全部品牌冒充类指标：content.js 评分阶段不产生 brandMatch，
  // background 二次核查（applyBrandCheck）直接放行
  const DEVELOPER_PLATFORM_DOMAINS = [
    'github.com', 'github.io', 'gitlab.com', 'gitee.com', 'bitbucket.org',
    'sourceforge.net', 'stackoverflow.com', 'stackexchange.com', 'npmjs.com',
    'pypi.org', 'crates.io', 'pkg.go.dev', 'csdn.net', 'juejin.cn',
    'cnblogs.com', 'segmentfault.com', 'oschina.net', 'zhihu.com',
    'jianshu.com', 'v2ex.com', 'mozilla.org'
  ];

  // ===== v2.1.5：搜索引擎豁免表（品牌冒充检测专用）=====
  // 搜索结果页的 <title> 必然包含用户查询词——搜"火绒官网下载"的百度页
  // 标题就是"火绒安全软件官网下载_百度搜索"，按品牌词匹配会被判
  // "非官方域上的品牌冒充"（误报）。命中本表（含子域名，如 cn.bing.com、
  // m.sm.cn、search.yahoo.com）时与开发者平台同样跳过品牌匹配。
  // 覆盖范围：全球综合 / Yandex 系 / AI 搜索 / 中国大陆 / 日韩俄欧区域引擎。
  // 新增条目须为搜索引擎方自营域名（豁免只跳过品牌评分层，
  // 黑名单/DNR 拦截层不受影响，误加自营域无放行恶意站风险）
  const SEARCH_ENGINE_DOMAINS = [
    // 全球综合
    'google.com', 'bing.com', 'duckduckgo.com', 'yahoo.com',
    'ecosia.org', 'startpage.com', 'qwant.com', 'mojeek.com',
    'kagi.com', 'lycos.com', 'ask.com', 'metager.de',
    // Yandex 系：地区站的 ccTLD 后缀不同（.ru/.com.tr），一个后缀盖不全，逐个列出
    'yandex.com', 'yandex.ru', 'yandex.com.tr', 'ya.ru',
    // AI 搜索
    'perplexity.ai', 'you.com', 'phind.com', 'search.brave.com', 'copilot.microsoft.com',
    // 中国大陆
    'baidu.com', 'sogou.com', 'so.com', 'sm.cn', 'chinaso.com', 'so.toutiao.com',
    // 日韩俄欧区域引擎
    'naver.com', 'daum.net', 'yahoo.co.jp', 'goo.ne.jp',
    'go.mail.ru', 'rambler.ru', 'seznam.cz'
  ];

  // ===== v2.3.0：可信 AI 对话平台豁免表 =====
  // 对话页面是 AIGC + UGC 混合语料：正文包含用户输入与模型输出的任意内容
  //（用户可能让 AI"帮我写一个卖火绒软件的官网文案"，页面文本随即出现全套
  // 话术/品牌词/备案号模板）。针对"下载站/官网"设计的文本启发式指标在此
  // 全部失真。命中本表（含子域名）的页面：
  //   1) 跳过品牌匹配——对话中提及品牌是问答语境，不是冒充
  //   2) 不加"大量表情符号"分——AI 回复天然高频使用表情符号
  //   3) ICP 备案三通道整体跳过（含后台 API 核验）——对话里出现的任何备案号
  //      都是内容而非页脚声明，"盗用备案"惩罚不能落在平台头上
  // 后台侧（applyBrandCheck / enhanceScoreAsync / queryDomainIntel）同表判定。
  // 新增条目须为 AI 对话方自营域名（黑名单/DNR 拦截层不受影响）
  const AI_CHAT_PLATFORM_DOMAINS = [
    // 国际主流
    'chatgpt.com', 'openai.com', 'claude.ai', 'gemini.google.com', 'grok.com',
    'x.ai', 'copilot.microsoft.com', 'chat.mistral.ai', 'mistral.ai',
    'poe.com', 'character.ai', 'perplexity.ai',
    // 中国大陆主流
    'deepseek.com', 'kimi.moonshot.cn', 'moonshot.cn', 'kimi.com',
    'yiyan.baidu.com', 'tongyi.aliyun.com', 'tongyi.com', 'chatglm.cn',
    'bigmodel.cn', 'doubao.com', 'yuanbao.tencent.com', 'xinghuo.xfyun.cn',
    'chat.qwen.ai', 'qwen.ai', 'tiangong.cn', 'chat.minimaxi.com'
  ];

  function isAiChatHostname(hostname) {
    hostname = String(hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    return AI_CHAT_PLATFORM_DOMAINS.some(function(domain) {
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  }

  // ===== v2.4.0：UGC 平台豁免表 =====
  // 帖子/视频标题/评论/弹幕是用户生成内容（UGC），与 AI 对话页同理：
  //   1) 跳过品牌匹配——视频标题"火绒测评"、微博提到某品牌是内容语境不是冒充
  //   2) 不加"大量表情符号"分——弹幕/评论/动态天然高频使用表情符号
  //   3) 不加"官方/安全/正版三类话术"分——帖子正文出现这些词是普通表达
  //   4) ICP 备案三通道整体跳过——帖子里粘贴任意备案号文本都是内容
  // 与 AI 对话的差异（UGC 特性适配）：
  //   - 外链核查单批上限更高（15→30）：评论区/简介区外链密度远大于对话输出，
  //     且评论区是银狐投毒的主投放渠道（伪装破解/补丁/网盘链接），核查更重要；
  //   - 收录平台自营短链域（t.cn / b23.tv / xhslink.com）——沙箱探测会跟随
  //     重定向核对最终落地域，短链跳转钓鱼恰好是该通道的核心抓捕形态。
  // 注意：泛主域（baidu.com/qq.com）刻意不收——只精确收录内容子域，
  // 防止豁免面误扩大到网盘等其他业务
  const UGC_PLATFORM_DOMAINS = [
    // 视频与直播
    'bilibili.com', 'b23.tv', 'bilibili.tv',
    'douyin.com', 'iesdouyin.com',
    'kuaishou.com', 'gifshow.com',
    'douyu.com', 'huya.com',
    'youtube.com', 'youtu.be',
    // 社交与社区
    'weibo.com', 'weibo.cn', 't.cn',
    'xiaohongshu.com', 'xhslink.com',
    'zhihu.com', 'douban.com', 'hupu.com',
    'tieba.baidu.com', 'baijiahao.baidu.com', 'mp.weixin.qq.com',
    // 论坛与资讯
    'toutiao.com', 'ngabbs.com', 'bbs.nga.cn', 'nga.cn',
    // 国际社区
    'reddit.com', 'x.com', 'twitter.com'
  ];

  function isUgcHostname(hostname) {
    hostname = String(hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    return UGC_PLATFORM_DOMAINS.some(function(domain) {
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  }

  // ===== v2.5.0：安全研究论坛表 =====
  // 卡饭/看雪/52pojie/T00ls 等安全技术论坛：帖子内容是专业 UGC 且天然高频
  // 提及杀软品牌、样本行为、备案号等——文本启发式全部失真，与 UGC 同列豁免
  //（仅保留 noah/adseo 等强特征与黑名单/DNR 拦截层）。特有逻辑：
  //   1) 进入论坛即注入顶部提示卡片（面向小白的完整风险告知），
  //      支持「我知道了」（本次收起）与「一键加白此论坛」（永久，写 storage
  //      的 whitelist 键，与 popup/warning 页同一协议）；
  //   2) 未加白时点击任何跨站外链弹窗拦截确认，支持「仅本次允许访问」；
  //   3) 不激活外链徽标核查通道（aiChatActive 不含本表）
  const SECURITY_FORUM_DOMAINS = [
    'kafan.cn',       // 卡饭论坛（bbs.kafan.cn 等）
    'pediy.com',      // 看雪学院（bbs.pediy.com 等，旧域）
    'kanxue.com',     // 看雪论坛（bbs.kanxue.com，现用主域）
    '52pojie.cn',     // 吾爱破解论坛
    't00ls.com',      // T00ls 安全小组
    't00ls.net'       // T00ls 备用域
  ];

  function isSecurityForumHostname(hostname) {
    hostname = String(hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    return SECURITY_FORUM_DOMAINS.some(function(domain) {
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  }

  // ===== 命名空间导出（幂等）=====
  global.__YH_CORE__ = global.__YH_CORE__ || Object.freeze({
    // 配置
    DEBUG: DEBUG, LOG: LOG, LOG_PREFIX: LOG_PREFIX, debug: debug,
    HARDCODED_DOMAINS: HARDCODED_DOMAINS,
    RULE_SOURCE_URLS: RULE_SOURCE_URLS,
    CLOUD_WHITELIST_URL: CLOUD_WHITELIST_URL,
    BRAND_SOURCE_URL: BRAND_SOURCE_URL,
    DEFAULT_WHITELIST: DEFAULT_WHITELIST,
    FETCH_TIMEOUT_MS: FETCH_TIMEOUT_MS,
    OFFSCREEN_WAIT_MS: OFFSCREEN_WAIT_MS,
    // 域名/品牌纯函数
    matchesPatternDomain: matchesPatternDomain,
    matchesDomainList: matchesDomainList,
    matchesBlockedDomain: matchesBlockedDomain,
    getRegistrableDomain: getRegistrableDomain,
    isSameSiteHost: isSameSiteHost,
    isGovCnHostname: isGovCnHostname,
    levenshteinWithin1: levenshteinWithin1,
    isShortLatinKeyword: isShortLatinKeyword,
    shortKeywordBoundaryHit: shortKeywordBoundaryHit,
    brandDomainKeywordHit: brandDomainKeywordHit,
    // 平台豁免表与判定
    DEVELOPER_PLATFORM_DOMAINS: DEVELOPER_PLATFORM_DOMAINS,
    SEARCH_ENGINE_DOMAINS: SEARCH_ENGINE_DOMAINS,
    AI_CHAT_PLATFORM_DOMAINS: AI_CHAT_PLATFORM_DOMAINS,
    UGC_PLATFORM_DOMAINS: UGC_PLATFORM_DOMAINS,
    SECURITY_FORUM_DOMAINS: SECURITY_FORUM_DOMAINS,
    isAiChatHostname: isAiChatHostname,
    isUgcHostname: isUgcHostname,
    isSecurityForumHostname: isSecurityForumHostname
  });
})(globalThis);
