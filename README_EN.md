<div align="center">

# Silver Fox Interceptor (银狐拦截系统)

**Chrome / Edge MV3 Extension · Blocks "Silver Fox" Trojan phishing / impersonation / seeding sites**

English | [简体中文](README.md)

</div>

---

## Notice (声明)

> This project is an upgrade and optimization of the **Silver Fox Interceptor System**, open-sourced under the MIT license.
>
> **Original Author**:
>
> - GitHub: [GitHub](https://github.com/YYT-2013)
> - Bilibili: [Bilibili](https://space.bilibili.com/1222118214?)
>
> **Original Project Distribution**:
>
> - GitHub repository: [GitHub](https://github.com/YYT-2013/yinhu-site-blocker)
> - Kafan forum: [Kafan](https://bbs.kafan.cn/thread-2293717-1-1.html)
>
> **Note**: This project's ICP record lookup implementation references another independent open-source project, VirusDetector (also open-sourced under the MIT license). It is **NOT** the base project of this repo. [GitHub](https://github.com/Lolitide/VirusDetector)

## About

The "Silver Fox" (银狐) Trojan is from an active seeding group in China that lures victims into downloading malware disguised as legitimate software (remote tools, cracked patches, security-software sites). This extension uses a **four-layer protection architecture** to detect and block the Silver Fox distribution chain — fake vendor sites, seeded forums, and AI-generated phishing links.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               Four-Layer Protection (all required)           │
├──────────┬──────────────────────────────────────────────────┤
│ Layer 1  │ DNR redirect: direct main_frame navigation        │
│ Layer 2  │ webNavigation.onBeforeNavigate fallback intercept │
│ Layer 3  │ Content script + MAIN world inject: block fetch   │
│ Layer 4  │ Scoring engine: 30 weighted risk indicators       │
└──────────┴──────────────────────────────────────────────────┘
```

## Modules

```
modules/
├── core.js                    Shared SSOT (config + domain utils + 5 exemption tables)
├── sandbox-probe.js           AI-link anti-tracking sandbox probe
├── domain-intel.js            Domain intel (RDAP age + ICP multi-source)
├── user-trust.js              User trust memory (host-level 7-day human pass)
├── ai-link.js                 AI/UGC link checking (5-level verdict + cache persist)
├── dnr-rules.js               DNR dynamic rules lifecycle
├── settings-store.js          Settings SSOT (defaults + normalization)
└── content/
    ├── verify-card.js         CONAC badge detection + floating verify card
    ├── link-scan.js           AI/UGC link badge + detail panel
    └── sec-forum.js           Security forum notice card + offsite link block
```

## Features

### Detection Tiers

| Tier | Condition | Behavior |
|------|-----------|----------|
| 🔴 Hard block | score ≥150 with ≥2 evidence categories, or blocklist / strong signal | Redirect to warning page (score detail + official-site guide) |
| 🟡 Soft block | score 100–149 with structural/resource evidence | Warning banner + freeze page (unfreezeable) |
| 🔵 Low-tier notice | score 80–99 | Thin gray-blue banner (browsing uninterrupted) |
| ⚪ Hint card | score 60–79 or brand-impersonation suspicion | Floating card bottom-right |

### Smart Platform Exemption

Detection strategy auto-switches based on site content type:

| Platform | Exemptions | Link check | Examples |
|----------|-----------|-----------|----------|
| **AI Chat** (28 domains) | brand/emoji/speech/ICP all skipped | ✅ batch 15 | ChatGPT, DeepSeek, Kimi, Qwen… |
| **UGC sites** (29 domains) | same as above | ✅ batch 30 | Bilibili, Weibo, Zhihu, Tieba… |
| **Security forums** (6) | same + notice card + offsite link block | ❌ | Kafan, Kanxue, 52pojie, T00ls… |
| **Search engines** (34) | brand matching skipped | — | Google, Baidu, Bing… |
| **Developer platforms** (21) | brand matching skipped | — | GitHub, StackOverflow… |

### AI / UGC Link Checking

Links in AI chat and UGC platforms are a hotspot for hallucinated domains, phishing, and compromised sites.

- **5-level verdict**: 🔴 Danger / 🟠 Suspicious / 🟢 Safe / ⚪ Unknown / 🔵 Checking
- **Anti-tracking sandbox probe**: no cookies, no referer, no cache, no body read, 8s timeout; SSRF-protected (blocks internal/loopback/reserved addresses, DNS-over-HTTPS pre-resolution)
- **Verdict philosophy**: probe failure ≠ suspicious, no-result ≠ suspicious — only confirmed evidence marks orange/red
- **Micro badge**: 16px inline capsule next to link, layout-flow preserving; hover/click shows check detail

### False-Positive Reduction

Fine-grained exemptions tuned per platform so legitimate sites aren't killed:

- AI chat pages: brand/emoji/speech/ICP fully skipped (text heuristics unreliable on AIGC/UGC)
- Security forums: same exemptions + notice card
- Speech-score cap at 25 (pure copy stacking alone can't reach block tier)
- Negated-context removal ("not official site", "not safe" don't count)
- ICP number base/sequence stripping (prevents luogu.com.cn class false positives)
- Short-keyword strong-boundary matching (prevents cline.bot misjudged as LINE)
- 55 search-engine/developer-domain brand exemptions

### Settings Panel

Chrome extension menu → "Options". Sections: General / Download Protection / Script Blocking / Location & Anti-Tracking / About. All toggles persist to storage.local, synced both ways with the background via message channel.
## Installation

1. Download the repo or `git clone`
2. Open `chrome://extensions/` (`edge://extensions/` on Edge)
3. Enable "Developer mode" (top-right)
4. Click "Load unpacked" and select this directory

## Files

| File | Description |
|------|-------------|
| `manifest.json` | MV3 config |
| `background.js` | SW main logic (verdict + message routing + DNR wiring) |
| `content.js` | Content script main (scoring + freeze + banners + toasts) |
| `modules/core.js` | Shared SSOT (config + pure fns + exemption tables) |
| `modules/sandbox-probe.js` | Anti-tracking sandbox probe |
| `modules/domain-intel.js` | Domain intel (RDAP/ICP) |
| `modules/user-trust.js` | User trust memory |
| `modules/ai-link.js` | AI/UGC link checking |
| `modules/dnr-rules.js` | DNR rules lifecycle |
| `modules/settings-store.js` | Settings SSOT |
| `modules/content/verify-card.js` | Badge detection + verify card |
| `modules/content/link-scan.js` | Link badge + panel |
| `modules/content/sec-forum.js` | Security forum protection |
| `options/` | Settings panel |
| `popup.html/js` | Popup (status / whitelist) |
| `warning.html/js` | Warning page |
| `offscreen.js` | Offscreen rules fetch |
| `brands.json` | Built-in brand library |

## License

This project is open-sourced under the [MIT License](LICENSE). The original [Silver Fox Interceptor System](https://github.com/YYT-2013/yinhu-site-blocker) is also MIT-licensed.