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

## 修改时必须同步的多处代码

- `HARDCODED_DOMAINS`：background.js 与 content.js 两处
- `RULE_SOURCE_URLS`：background.js / offscreen.js / popup.js 三处
- 默认白名单：background.js `DEFAULT_WHITELIST` 与 popup.js `BUILT_IN_WHITELIST`
- `AI_CHAT_PLATFORM_DOMAINS` / `isAiChatHostname`（v2.3.0 可信 AI 对话平台豁免）：background.js 与 content.js 各一份，修改需两处同步；豁免语义=跳过品牌匹配 + manyEmoji/officialSpeech 不加分 + ICP 三通道与后台 API 核验全跳过，黑名单/DNR 层不受影响
- `matchesPatternDomain` / `isGovCn` / `levenshteinWithin1` 等工具函数在 background.js 与 content.js 各有一份，语义需保持一致
- `uiLevelOf`（UI 层级判定 warn/notice/card/clear）：background.js 同步决策与 enhanceScoreAsync 对账共用同一规则，修改阈值时两处及 content.js 展示层同步
- UI 层级切换统一走 content.js `applyScoreVerdict()`：同步回执与异步对账（scoreAdjusted）共用，新增层级相关逻辑时勿在分支里单独注入/移除 UI；同步回执必须携带 `effectiveTotal`（后台实际判定分），否则状态记录不一致会导致去重失效
- Toast 触发语义（v2.2.5）：仅在**拦截方式**（UI 层级 blocked/warn/notice/card/clear）实际切换且非首次应用时弹出，同方式内分数波动与卡片增减一律静默；15 秒防抖冷却抑制阈值抖动反复弹（scoreEscalated 硬拦截升级豁免冷却）
- 硬拦截升级提示：background.js 跳警告页前发 `scoreEscalated` 并延迟 1.6s 再 `tabs.update`

## 参考项目

`一个优秀的开源项目，可以参考一下/` 目录是 VirusDetector 开源项目的完整源码（本项目 RDAP/ICP 异步增强的设计参考），仅作参考，不属于扩展本体。
