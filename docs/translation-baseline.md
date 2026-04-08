# LOHA Translation Baseline

This document defines the repository-wide translation baseline for LOHA's locale catalogs and user-facing documentation.

General rules in this document apply to every locale. Locale-specific rules apply only to the locale named in that section.

It applies to:

- `locales/*.toml`
- `docs/*.md`
- `README.md`
- `README_zh_CN.md`
- `MANUAL.md`
- `MANUAL_zh_CN.md`
- future LOHA-facing docs and UI copy

## How to Use This Document

- Use the general rules below for any translation or localization work.
- Use a locale-specific section only when translating into that locale.
- If a future locale needs substantial glossary or style guidance, add a new locale-specific section or split it into `docs/i18n/<locale>-style-guide.md`.

## Source of Truth

| Asset type | Semantic source |
| --- | --- |
| Locale catalogs | [`locales/en_US.toml`](../locales/en_US.toml) is the canonical source for locale keys, placeholders, and UI-level English semantics. |
| Public repo docs under `docs/` | English files are the public source unless a file is intentionally locale-scoped. |
| Localized long-form docs | Each localized document must stay aligned with the corresponding English public doc for behavior, scope, and change tracking. During the current Simplified Chinese sync, `README_zh_CN.md` and `MANUAL_zh_CN.md` are the active editorial baseline for `zh_CN` coverage. |
| Runtime behavior | The Python implementation under `src/loha/` is the final authority when docs or locale wording drift from actual behavior. |

## General Translation Rules

| Rule | Requirement |
| --- | --- |
| Code wins on accuracy | If documentation wording conflicts with current runtime behavior, fix the documentation to match the code instead of preserving historical phrasing. |
| `en_US` is the semantic source | For locale strings, `locales/en_US.toml` is the canonical source for keys, placeholders, fallback wording, and literal token preservation. |
| Public docs language | Files under `docs/` should use natural English in the public repository unless a specific file is intentionally published as locale-scoped content. |
| Localized docs track source behavior | Localized docs should preserve the source document's behavior and coverage, but may rewrite sentence order, headings, and paragraph structure to read naturally in the target locale. |
| Stable concept mapping | One English concept should map to one primary target-locale term unless a locale-specific section explicitly allows a narrower variant. |
| Preserve placeholders exactly | Keep placeholder names, count, and order unchanged across locale catalogs. |
| Keep literal identifiers | Do not translate config keys, command names, flags, file paths, code identifiers, protocol names, or kernel mechanism names. |
| Preserve technical tokens | Keep literal forms such as `EXTERNAL_IFS`, `LISTEN_IPS`, `AUTH_MODE`, `CONNTRACK_MODE`, `ct mark`, `ct label`, `rp_filter`, `conntrack`, `nftables`, `systemd`, `reload --full`. |
| Do not backslide to stale copy | If an older locale string or historical doc still uses deprecated wording, fix the stale asset instead of conforming to it. |
| Add locale-specific guidance deliberately | When a locale needs glossary rules, forbidden variants, or style exceptions, document them in that locale's section instead of overloading the general rules. |

## Locale Catalog Rules

- The key set must match `locales/en_US.toml`.
- Placeholder sequences must remain identical to the source locale.
- Literal tokens required by the locale catalog lint metadata must remain unchanged when they appear in the source text.
- Locale-specific terminology constraints should be encoded in locale catalog lint metadata when practical, so they can be checked automatically.

## English Source Writing Rules

English source documentation must follow these rules:

- It must not read like sentence-by-sentence translation from another language.
- It must read like native technical documentation for Linux, networking, and ops audiences.
- It must stay natural, accurate, restrained, and terminologically stable.
- It should preserve the source material's information density, but sentence order, paragraph structure, and headings may be rewritten when that improves clarity.
- If localized copy is imprecise, follow the code and `locales/en_US.toml` rather than copying the ambiguity back into English.

## Locale-Specific Rules: `zh_CN`

This section defines the active Simplified Chinese baseline for LOHA. Future locales should add their own sections or dedicated style-guide files without weakening the repository-wide rules above.

Simplified Chinese localization must follow these rules:

- Write natural, technically precise Simplified Chinese for Linux, networking, and ops audiences.
- Keep one primary Chinese term per LOHA concept unless the glossary below explicitly allows a narrower scoped variant.
- Prefer semantically accurate LOHA terms such as `外部` / `内部` over narrower Internet-specific wording such as `公网` / `内网` when the English source is broader.
- Do not alternate between `网卡` / `接口`, `接管` / `管理`, `监听` / `对外暴露`, or `并发连接数` / `conntrack` for the same product concept.
- Keep technical literals such as `ct mark`, `ct label`, `rp_filter`, and `conntrack` unchanged.

### `zh_CN` Terminology Baseline

| English source term | Standard Chinese | Avoid / deprecated variants | Scope / notes |
| --- | --- | --- | --- |
| external | external / 外部侧 | 公网侧 | Refers to the side outside protected internal networks. It does not necessarily mean globally routable public Internet addresses. |
| internal | internal / 内部侧 | 内网侧 | Refers to the protected internal side. |
| external interface | 外部接口 | 外网网卡, 外网接口 | Use for `EXTERNAL_IFS` and related UI text. Prefer `接口` over `网卡`. |
| primary external interface | 主外部接口 | 主外网接口 | Use for `PRIMARY_EXTERNAL_IF`. |
| internal interface | 内部接口 | 内网网卡, 内网接口 | Use for `LAN_IFS` and validation-related prompts. |
| internal network | 内部网络 | 内网网段, 内网 | Use for the semantic concept, not raw CIDR text. |
| exposed | 对外暴露 | 发布 | Use for services or addresses that LOHA intentionally makes reachable from the external side. |
| external IPv4 addresses used for exposure | 对外暴露用外部 IPv4 地址 | 已发布外部 IP, 发布用外部 IPv4 地址 | Use in prompts, summaries, and installer docs. |
| exposed services | 对外暴露的服务 | 已发布服务 | Use when traffic is intentionally reachable from the external side. |
| exposed backends | 对外暴露的后端 | 已发布后端 | Use in protection-scope summaries and prompts. |
| exposure and protection | 对外暴露与保护 | 发布与保护 | Section title in installer summary and docs. |
| protection | 保护 | 防护 | Use for LOHA's forwarding-protection semantics unless the text is explicitly about broader hardening. |
| protection mode | 保护模式 | 保护范围 | Use for `PROTECTION_MODE` as a config concept. |
| protection scope | 保护范围 | 保护模式 | Use in summaries describing the resulting behavior. |
| protected networks | 受保护网络 | 指定网段 | Use when `PROTECTED_NETS` is the subject. |
| default egress NAT | 默认出口 NAT | 默认出网 NAT | Use for section titles and behavior descriptions. |
| default egress SNAT | 默认出口 SNAT | 默认出网 SNAT | Use for the explicit setting controlled by `ENABLE_EGRESS_SNAT`. |
| default egress source IP | 默认出口源 IP | 默认 SNAT IP | Use in summaries. |
| authorization mode | 授权模式 | 认证模式 | Use for `AUTH_MODE` prompts, summaries, and docs. |
| authorization | 授权 | 认证 | Use for the general forwarding-authorization concept. |
| mark mode | `ct mark` 模式 | mark 模式 | Keep `ct mark` literal. |
| label mode | `ct label` 模式 | label 模式, 标签模式 | Keep `ct label` literal. |
| runtime binding | 运行时绑定 | 运行时兼容 | Use for `EXTERNAL_IFS` / `LISTEN_IPS` binding checks. |
| external interface binding | 外部接口绑定 | 运行时外网接口 | Use in runtime summary and doctor output. |
| exposure address binding | 对外暴露地址绑定 | 已发布地址绑定 | Use in runtime summary and doctor output. |
| rp_filter | `rp_filter` | 反向路径过滤 | Keep the kernel parameter name literal. |
| conntrack | `conntrack` | 连接跟踪表, 并发连接数 | Keep the subsystem name literal. |
| reload | `reload` / 重新加载 | 重载 | Keep the command literal as `reload`. |
| reload --full | `reload --full` / 完整重建 | 完整重建, 全量重建 | Keep the command literal untouched and prefer rebuild wording over restart wording. |
| full rebuild | 完整重建 | 全量重建 | Use in prose for the control-plane effect. |

### Literal Tokens That Stay Untranslated in `zh_CN`

The following categories must remain unchanged in Simplified Chinese text:

- Config keys: `EXTERNAL_IFS`, `PRIMARY_EXTERNAL_IF`, `DEFAULT_SNAT_IP`, `LAN_IFS`, `LAN_NETS`, `LISTEN_IPS`, `PROTECTION_MODE`, `PROTECTED_NETS`, `ENABLE_EGRESS_SNAT`, `EGRESS_NETS`, `ENABLE_STRICT_LAN_VALIDATION`, `INTERNAL_IFS`, `TRUSTED_INTERNAL_NETS`, `AUTH_MODE`, `CONNTRACK_MODE`
- Commands and flags: `loha`, `loha reload`, `loha reload --full`, `loha rules render`, `loha doctor`, `loha config wizard`, `--dry-run`, `--non-interactive`, `--purge`
- Paths and filenames: `/etc/loha/loha.conf`, `/etc/loha/rules.conf`, `/etc/sysctl.d/90-loha-forwarding.conf`
- Kernel and firewall syntax: `ct mark`, `ct label`, `rp_filter`, `conntrack`, `nftables`, `systemd`
