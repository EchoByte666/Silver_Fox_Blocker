# 银狐拦截系统

Chrome/Edge MV3 浏览器扩展：拦截"银狐"木马钓鱼/仿冒网站。

## 工作流规则（必须遵守）

- **每次完成更改后必须提交 GIT**：任何修改完成并通过验证后，立即 `git add` + `git commit`，提交信息用中文简述本次更改内容。不要等用户提醒。

## 项目架构

四层防护（background.js 头部注释为准）：

1. **DNR 重定向** — main_frame 导航层直接重定向到警告页
2. **webNavigation.onBeforeNavigate** — 导航事件兜底拦截
3. **内容脚本 + 主世界注入** — 拦截页面内部 fetch/XHR 恶意请求
4. **页面评分引擎** — 30 项风险指标评分；≥150 分硬拦截跳警告页；100~149 软拦截（警示横幅 + 页面冻结）；80~99 低权重提示横幅

## 文件职责

| 文件 | 职责 |
|------|------|
| manifest.json | MV3 配置（v2.x） |
| background.js | SW 核心：远程规则拉取、DNR 规则、品牌核查、评分决策、RDAP 域龄/ICP 备案异步增强 |
| content.js | 首屏同步检测、警示横幅、冻结/解冻、CONAC 官方标识豁免、悬浮验证卡片 |
| offscreen.js | Offscreen 文档拉取远程规则（fetch/XHR 兜底） |
| popup.html/js | 弹窗：状态展示、白名单管理、手动刷新规则 |
| warning.html/js | 警告页：评分明细、品牌冒充引导、主题切换 |
| brands.json | 内置品牌库（品牌冒充检测用） |
| default_rules.txt | 内置默认黑名单兜底 |

## 模块化结构（v2.7.0）

- `modules/core.js`：**单一事实来源（SSOT）**——日志（DEBUG/LOG/LOG_PREFIX/debug）、HARDCODED_DOMAINS、RULE_SOURCE_URLS、CLOUD_WHITELIST_URL、BRAND_SOURCE_URL、DEFAULT_WHITELIST、FETCH_TIMEOUT_MS、OFFSCREEN_WAIT_MS、matchesPatternDomain/matchesDomainList/matchesBlockedDomain、getRegistrableDomain/isSameSiteHost、isGovCnHostname（统一含 gov.hk/政务.cn 扩展后缀，content 首屏快筛语义随之加宽至与后台一致）、levenshteinWithin1、isShortLatinKeyword/shortKeywordBoundaryHit/brandDomainKeywordHit、五张平台豁免表（DEVELOPER/SEARCH_ENGINE/AI_CHAT/UGC/SECURITY_FORUM）与 isAiChatHostname/isUgcHostname/isSecurityForumHostname。改配置或这些函数只改此文件。加载方式：manifest content_scripts js 数组首位 + background.js 顶部 importScripts 首位；文件内禁止 import/export 与触碰 chrome.*/DOM（经典脚本两栖环境）；命名空间 `globalThis.__YH_CORE__`，消费方解构
- `modules/sandbox-probe.js`：AI 外链沙箱防追踪探测独立模块（sandboxProbeUrl/doSandboxProbe + 注册域级缓存/并发去重/8s 超时；PROBE_CACHE_TTL_MS/PROBE_CACHE_MAX/AI_LINK_PROBE_TIMEOUT_MS 模块自持）；依赖 core.js 先加载；命名空间 `globalThis.__YH_SANDBOX__`
- `modules/domain-intel.js`（v2.7.1）：域名情报——RDAP 域龄五通道（IANA→硬编码表→rdap.org→WhoDat→whoisjs）+ ICP 备案两源 + `icpNumbersMatch`；依赖 core；命名空间 `__YH_DOMAIN_INTEL__`
- `modules/user-trust.js`（v2.7.1）：用户信任记忆（`yhUserTrust` storage.local，惰性加载/防抖写回/LRU），导出 TTL/DISCOUNT 常量；命名空间 `__YH_USER_TRUST__`
- `modules/ai-link.js`（v2.7.1）：AI/UGC 外链核查全部逻辑（五级结论/缓存持久化/可疑信号/品牌仿冒/ICP 裁决/批次），运行时状态经 `init(deps)` 注入；命名空间 `__YH_AI_LINK__`
- `modules/dnr-rules.js`（v2.7.1）：DNR 动态规则（分批/全量替换/串行），经 `init(deps)` 注入 getBlocklist/getAllowedDomains；命名空间 `__YH_DNR__`
- `modules/content/verify-card.js`（v2.7.1）：CONAC 官方标识检测 + 悬浮验证卡片；命名空间 `__YH_VERIFY__`
- `modules/content/link-scan.js`（v2.7.1）：AI/UGC 外链徽标+面板核查；导出于 scheduleLinkScan；命名空间 `__YH_LINK_SCAN__`
- `modules/content/sec-forum.js`（v2.7.1）：安全论坛提示卡+站外链拦截；自判激活
- 模块加载顺序：manifest content_scripts = core → verify-card → content → link-scan → sec-forum；background importScripts = core → sandbox-probe → domain-intel → user-trust → ai-link → dnr-rules。SW 类模块的状态依赖一律经 `init(deps)` 依赖注入（模块不直接引用 SW 全局集）；content 类模块在 DOM 上下文按序加载，IIFE 内自动短路
- 二期路线（v2.7.0 的计划）已基本完工：bg 仅剩增强对账/message 路由/初始化/事件监听；content 主 IIFE 保留评分引擎/冻结/横幅/Toast；popup/offscreen 副本收敛 + `type:module` 升级 + 消息路由分离仍留作后续
- 平台豁免语义速查：AI_CHAT/UGC/SECURITY_FORUM 三表=跳过品牌匹配 + manyEmoji/officialSpeech 不加分 + ICP 三通道与后台 API 核验全跳过（黑名单/DNR 拦截层不受影响）；UGC 另激活外链核查通道且单批 30（AI 对话 15）；论坛不激活外链核查，特有=提示卡片 + 未加白站外链接拦截（content.js 末尾模块）
- 仍存在的重复副本（二期收敛目标）：popup.js 与 offscreen.js 的 `RULE_SOURCE_URLS`、popup.js 的 `BUILT_IN_WHITELIST`
- 二期路线：manifest background 加 `"type": "module"` 升级 ES modules（切换前需全量排查隐式全局赋值）；随后继续拆分 background.js（rdap/icp 域名情报、ai-link 分类与 verdict 缓存、user-trust 信任记忆、dnr 规则、消息路由）与 content.js（评分引擎/冻结/外链核查/论坛防护等功能域）

## 修改时必须同步的多处代码

- `RULE_SOURCE_URLS`：offscreen.js / popup.js 各有一份副本（权威源=modules/core.js）
- 默认白名单：popup.js `BUILT_IN_WHITELIST`（权威源=modules/core.js `DEFAULT_WHITELIST`）
- `uiLevelOf`（UI 层级判定 warn/notice/card/clear）：background.js 同步决策与 enhanceScoreAsync 对账共用同一规则，修改阈值时两处及 content.js 展示层同步
- UI 层级切换统一走 content.js `applyScoreVerdict()`：同步回执与异步对账（scoreAdjusted）共用，新增层级相关逻辑时勿在分支里单独注入/移除 UI；同步回执必须携带 `effectiveTotal`（后台实际判定分），否则状态记录不一致会导致去重失效
- Toast 触发语义（v2.2.5）：仅在**拦截方式**（UI 层级 blocked/warn/notice/card/clear）实际切换且非首次应用时弹出，同方式内分数波动与卡片增减一律静默；15 秒防抖冷却抑制阈值抖动反复弹（scoreEscalated 硬拦截升级豁免冷却）
- 硬拦截升级提示：background.js 跳警告页前发 `scoreEscalated` 并延迟 1.6s 再 `tabs.update`
- 评分误报治理（v2.6.0）：`manyEmoji` 语料改为作者语料（title/h1/meta）且证据类别归入 `speech`——不再满足 hasHardEvidence 冻结门槛；speech 类正分合计封顶 `SPEECH_CAP_PTS=25`（content.js scorePage 内，超出以 id=speechCap 负分明细展示）；officialSpeech 统计需剔除否定前缀（非/不/无/没）命中。修改任一项时注意 popup/warning 页明细展示兼容
- 连字符模式域名异步校平：content scorePage 返回 `patternDomainHit` 标记，background enhanceScoreAsync 反查 ICP（持有有效备案 `PATTERN_DOMAIN_ICP_BONUS=-20` / 明确查无 `+8` / API 不可用不动分值），执行条件（!icpClaimed 且非可信内容平台）与常量修改需保持 content/background 语义同步
- 用户信任记忆：storage.local 键 `yhUserTrustMap`（host→ts，TTL `USER_TRUST_TTL_MS` 7 天、上限 500、800ms 防抖写回，SW 重启惰性加载）。登记入口=markUnfrozen→markUserTrusted；消费点两处语义必须一致——①scorePage 同步决策（先 await ensureUserTrustLoaded，命中则抵扣 `USER_TRUST_DISCOUNT=20` 分且回执 `unfrozen: isRecentlyUnfrozen||hostTrusted`）②enhanceScoreAsync 冻结指令加 `&& !isUserTrustedActive(hostname)`。黑名单/noah/adseo 强特征/DNR 拦截层**永不读取**信任表
- AI 外链形态可疑降档（classifyAiChatLink 尾段）：非品牌仿冒的可疑形态链接沙箱探测后按落点分档——同注册域落地或 HTTP≥400 → `unknown`（绿点+面板留依据）；仅跨注册域重定向维持 warn。疑似仿冒品牌域名**不走此降档**，强制进入 ICP 备案第二阶段裁决

## 参考项目

`一个优秀的开源项目，可以参考一下/` 目录是 VirusDetector 开源项目的完整源码（本项目 RDAP/ICP 异步增强的设计参考），仅作参考，不属于扩展本体。
