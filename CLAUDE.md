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
- `matchesPatternDomain` / `isGovCn` / `levenshteinWithin1` 等工具函数在 background.js 与 content.js 各有一份，语义需保持一致

## 参考项目

`一个优秀的开源项目，可以参考一下/` 目录是 VirusDetector 开源项目的完整源码（本项目 RDAP/ICP 异步增强的设计参考），仅作参考，不属于扩展本体。
