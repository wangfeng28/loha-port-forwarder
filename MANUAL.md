# LOHA Port Forwarder Manual

English | [简体中文](./MANUAL_zh_CN.md)

This manual is for readers who want to understand LOHA end to end, not just install it once and move on. The README tells you what the project is and whether it fits your setup. This manual explains the full operating picture: what LOHA is, why it fits certain host-side ingress layouts, how it works, how to install and run it, where the advanced features begin, what the current product boundary is, and where to start when something goes wrong.

If you only want the quick introduction, start with [README.md](./README.md).

## Contents

- [Terminology](#terminology)
- [1 Introduction](#1-introduction)
- [2 What LOHA Is and Who It Fits](#2-what-loha-is-and-who-it-fits)
- [3 Why Many Hosts Fit LOHA Well](#3-why-many-hosts-fit-loha-well)
- [4 How LOHA Works](#4-how-loha-works)
- [5 Requirements and Boundary](#5-requirements-and-boundary)
- [6 Install Uninstall Upgrade](#6-install-uninstall-upgrade)
- [7 Daily Use](#7-daily-use)
- [8 Rules File](#8-rules-file)
- [9 Advanced Features](#9-advanced-features)
- [10 Working Alongside Existing Firewalls](#10-working-alongside-existing-firewalls)
- [11 Troubleshooting](#11-troubleshooting)
- [12 FAQ](#12-faq)
- [13 Command Reference](#13-command-reference)
- [14 Docs Testing Translation](#14-docs-testing-translation)

## Terminology

- `external` means the side outside the protected internal networks. It does not necessarily mean globally routable public Internet space.
- `internal` means the interfaces and networks LOHA treats as the protected internal side.
- `exposed` means services or external IPv4 addresses that LOHA intentionally makes reachable from the external side.
- `authorization mode` means the kernel-level authorization state LOHA uses to distinguish intended forwarded traffic from everything else. `ct mark` and `ct label` are forwarding authorization mechanisms, not login or identity systems.
- `hot update` means preserving the current control-plane shape and updating mapping data where possible. `full rebuild` means rebuilding the full ruleset and control state.

## 1 Introduction

If this is your first serious read-through, the best path is:

1. Read sections 2 through 5 first to build the mental model.
2. Then read sections 6 through 9 for install, daily operations, and advanced behavior.
3. Use section 13 later as the command lookup reference.

This manual deliberately keeps the long command catalog near the end. The main body is meant to answer a different set of questions first:

- What LOHA actually is.
- Why some host-side ingress layouts are a particularly strong fit.
- How LOHA turns saved config into kernel rules.
- Which changes are ordinary day-to-day updates and which ones are structurally heavier.

If you already know LOHA and are coming back for a command, a troubleshooting path, or an advanced setting, feel free to jump directly to the section you need.

## 2 What LOHA Is and Who It Fits

LOHA is an `nftables`-based port-forwarding and NAT control layer for Linux hosts. It is built for a common host-side reality: public traffic lands on the Linux host first, then needs to be forwarded to a VM, container, or internal machine. LOHA does not try to wrap that host in a separate firewall appliance abstraction. Instead, it takes that native host path and makes it clearer, more reviewable, and easier to keep in good shape over time.

At a high level, LOHA combines three things:

- canonical core configuration in `loha.conf`
- aliases and forwarding rules in `rules.conf`
- a renderer and loader that turn those files into stable `nftables` rules and load them into the kernel

The name LOHA reflects four design priorities:

- **L**ightweight: the control plane steps in only for install, configuration, `reload`, and rollback; once rules are loaded, the data plane stays in the kernel's `nftables` path without needing a resident user-space forwarding process
- **O**bservable: core config, port rules, rendered output, runtime binding state, and diagnostic output all have explicit places to inspect, which makes review, comparison, and troubleshooting practical
- **H**ost-native: LOHA does not introduce a separate appliance-style firewall abstraction; it works directly with the host's existing `nftables`, `systemd`, `sysctl`, plain-text config, and normal service lifecycle
- **A**uthorization-driven: forwarding is not defined by a loose pile of bare `DNAT` rules; it is organized around explicit authorization state (`ct mark` / `ct label`) so authorization, allow-path decisions, miss cleanup, and protection-scope checks follow one control semantic

LOHA is a strong fit when:

- the ingress edge already lives on the Linux host instead of a separate firewall appliance
- you need to forward a small to medium set of external ports to VMs, containers, or internal hosts
- you want to keep host-native networking transparency without living inside a hand-maintained ruleset
- you want plain-text config that is easy to back up, script, and review
- you want the same tool to work for human operators, scripts, Ansible, and agents

LOHA is not trying to replace:

- a full firewall distribution
- a centralized multi-node policy system
- complex multi-WAN routing orchestration, symmetric return-path guarantees, or WAN-level HA and load balancing
- non-`systemd` workflows outside the documented current boundary

## 3 Why Many Hosts Fit LOHA Well

In many self-hosting setups, the real question is not whether you need a firewall. The real question is how to manage host-side ingress once the public edge is already on the host.

In practice, most setups drift toward one of two patterns:

- hand-maintained `nftables` or `iptables`
- a separate firewall VM in front of everything

Both can work. Both also move the cost somewhere else.

With hand-maintained rules, the problem is rarely the first few forwards. The problem shows up once the ruleset becomes a real system:

- change review gets harder
- overlap and ordering become harder to reason about
- rollback starts depending on manual edits, shell history, and memory

With a separate firewall VM, the tradeoff is different:

- you gain a stronger control point
- you also add another appliance, more resource use, more operational surface area, and another failure domain

LOHA is meant for the middle ground:

- the public edge is already on the host
- the main goal is to expose selected services cleanly
- you still want the host's own Linux networking stack to remain visible and in control

That is why many Proxmox VE hosts, Linux gateways, and homelab edge nodes are often a better fit for LOHA than "spin up another firewall VM just to manage these forwards."

## 4 How LOHA Works

### The Two Core Files

LOHA's day-to-day management revolves around two files:

- `/etc/loha/loha.conf` holds the core configuration, including the external interface model, the external IPv4 addresses used for exposure, internal networks, protection behavior, default egress NAT, authorization mode, and system-integration settings.
- `/etc/loha/rules.conf` holds aliases and port mappings, in other words the concrete "which protocol and port should go to which backend" data.

The split is intentional:

- `loha.conf` defines the topology and control-plane behavior.
- `rules.conf` defines the actual exposed mappings.

That is why "I changed a few ports" and "I changed the authorization mode" are not the same class of change in LOHA.

### How Authorization Modes Work

LOHA currently supports two authorization paths:

- `ct mark`
- `ct label`

Both serve the same goal: make it explicit in the kernel whether a flow is part of a valid exposed mapping and should be allowed to continue down the authorized forwarding path.

In the default `ct mark` path, the rough logic is:

1. write a dedicated authorization bit to the candidate flow
2. perform the mapping lookup
3. keep the authorized path on a hit
4. clear the authorization bit explicitly on a miss

The point is not that LOHA enjoys doing one extra metadata write. The point is that authorization state and real mapping hits stay bound together. That lets the `forward` path make clearer allow-or-drop decisions.

`ct label` keeps the same design goal but stores that state in `ct label` instead, which makes it easier to isolate LOHA from environments that already depend heavily on `ct mark`.

### How Rules Reach the Kernel

The main path looks like this:

1. Read canonical `loha.conf` and `rules.conf`.
2. Validate runtime binding and current boundary rules.
3. Render the forwarding data into `nftables` `map`, `set`, `define`, and fixed chain structures.
4. Apply the result to the kernel and persist control state.

Two ideas matter most here.

First, LOHA does not model each port forward as one more independent NAT rule in a long ordered chain. It collapses mappings into `map` lookups. That keeps the maintenance story from degrading linearly as the mapping set grows.

Second, LOHA is not just a `DNAT` generator. It also models which traffic is allowed to continue along the forwarding path, so forwarding, authorization, and protection behavior are designed together.

### Why There Is No Long Running User Space Forwarder

LOHA's long-lived data plane is in the kernel, not in a resident user-space forwarding process.

`loha.service` is currently a `oneshot`-style control-plane entry point. Its job is to render, validate, load, or update rules. Once those rules are in the kernel, the long-running data plane is the `nftables` ruleset itself, not a daemon proxying traffic in user space.

That has two direct consequences:

- the host still uses a native Linux forwarding path
- LOHA's ongoing footprint is about rules and system integration, not an extra traffic-handling daemon

### Hot Update and Full Rebuild

For routine port-rule changes, you normally run:

```bash
sudo loha reload
```

That means:

- `loha.service` must already be active
- the request goes through `systemd reload`
- the loader first attempts the lighter hot-update path

If the newly rendered result is still compatible with the existing control state, LOHA updates only the mapping objects such as maps and sets instead of rebuilding the whole table.

If the loader sees that the control state no longer matches, for example because you changed behavior that affects the control-plane skeleton, it internally upgrades that reload to a full apply. In other words, the command entry point is still the regular reload path for an already running service, but the loader decides whether the lightweight path is still safe.

For an explicit full rebuild, use:

```bash
sudo loha reload --full
```

That is the better fit when:

- `loha.service` is not currently running
- you want to rebuild the whole control plane on purpose
- you just changed a structural setting such as `AUTH_MODE`
- you want "config written" and "full rebuild executed" to remain two explicit steps

One practical point matters a lot:

- plain `reload` is not a "restart the service for me if needed" shortcut
- if the service is inactive or failed, go straight to `reload --full`

## 5 Requirements and Boundary

The documented runtime baseline is:

- Proxmox VE 7+, Debian 11+, Ubuntu 20.04+, or RHEL 9+
- Linux kernel 5.6+
- `nftables` 0.9.4+
- `Python` 3.8+
- `systemd`

Common runtime dependencies include:

- `python3`
- `nft`
- `ip`
- `sysctl`
- `systemctl`

Most management commands require root privileges. `loha version` is the main exception.

The current supported boundary should be understood like this:

- IPv4 is the main focus
- the documented control plane assumes `systemd`
- the supported mainline is one primary external interface plus one or more external IPv4 addresses used for exposure on that interface
- `DEFAULT_SNAT_IP` is an explicit primary value, not an implicit "first item wins" fallback

The current supported shape is:

- `single-external + multi-listen-ip`

not:

- full `multi-external`

The current release does not promise:

- full multi-external support
- symmetric "return through the same WAN" behavior
- multi-WAN HA or load balancing
- complex policy-routing orchestration
- full replacement of the host's existing firewall stack

If those are the center of your requirements, LOHA should not be your main tool.

## 6 Install Uninstall Upgrade

### Interactive Install

Start by obtaining the install files from GitHub Releases. The fastest path is the release bootstrap installer:

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/install.sh | sudo sh
```

If you want to inspect the install plan without changing the system first:

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/install.sh | sudo sh -s -- --dry-run
```

That bootstrap script downloads `loha-port-forwarder.tar.gz` and `loha-port-forwarder.tar.gz.sha256` from the same GitHub Release, verifies the checksum, unpacks a temporary working tree, and then runs the bundled `./install.sh`.

If you prefer to inspect the release files before running them, download and verify the archive manually:

```bash
curl -fsSLO https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/loha-port-forwarder.tar.gz
curl -fsSLO https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/loha-port-forwarder.tar.gz.sha256
sha256sum -c loha-port-forwarder.tar.gz.sha256
tar -xzf loha-port-forwarder.tar.gz
cd loha-port-forwarder
sudo ./install.sh
```

If GitHub CLI is available and you want provenance verification in addition to checksum verification, you can also run:

```bash
gh attestation verify loha-port-forwarder.tar.gz --repo wangfeng28/loha-port-forwarder
```

The installer's mainline flow is:

1. prechecks and existing-config import
2. network environment
3. exposure and protection
4. default egress NAT
5. advanced settings
6. summary and confirmation

For a first read, the best way to interpret that flow is:

1. choose the language
2. if `./loha.conf` or `/etc/loha/loha.conf` already exists, the installer selects one of them as the starting point
3. confirm the primary external interface, the external IPv4 addresses used for exposure, the primary external IP, the internal interfaces, and the internal networks
4. decide the protection scope, Hairpin NAT, and default egress NAT behavior
5. only then look at the advanced settings such as auth mode, WAN-to-WAN, TCP MSS Clamp, strict internal source validation, `RP_FILTER_MODE`, and `CONNTRACK_MODE`

Once installation finishes, verify the basics immediately:

```bash
sudo loha config show
sudo loha doctor
sudo loha list
sudo nft list table ip loha_port_forwarder
```

If you want a machine-readable post-install status, `sudo loha config show --json` now includes a `control_plane` summary with desired and applied revisions, pending actions, and the last apply result. That is the supported way to inspect LOHA's control-plane sync state; do not treat files under `/run/loha/` as something to edit by hand.

### Non Interactive Install and Dry Runs

The examples in this section assume you are running from an extracted release archive or a local working tree.

If you already have the config ready, use the non-interactive path:

```bash
sudo ./install.sh --non-interactive
```

If you want to inspect the plan without changing the system:

```bash
sudo ./install.sh --non-interactive --dry-run
```

In non-interactive mode, the starting-config priority is:

1. `./loha.conf`
2. `/etc/loha/loha.conf`
3. environment probing

The installer chooses one starting config. It does not merge two config files field by field.

A conservative non-interactive workflow is:

1. write the values you already know into `./loha.conf`
2. run `--dry-run`
3. install for real only after the plan looks correct
4. verify with `loha doctor` and `nft list table ip loha_port_forwarder`

### Config Persistence and Installed Layout

This section really comes down to three practical ideas.

First, `/etc/loha/loha.conf` is a config file owned by LOHA. It is not a shell script. The easiest way to think about it is as LOHA's own saved parameter sheet.

Its on-disk format is intentionally uniform:

```ini
KEY="VALUE"
```

In practice, the takeaway is:

- every key is saved in one consistent format
- the installer and `loha config` rewrite the whole file in a stable order
- older shell-style forms such as `export KEY="VALUE"` or `KEY = "VALUE"` are not part of the current supported path

Second, the installer and `loha config` still accept a few convenience shortcuts at input time, including:

- `EXTERNAL_IFS=auto`
- `LISTEN_IPS=auto`
- some recommendation-style toggle `auto` inputs

But those shortcuts do not persist as-is in `/etc/loha/loha.conf`. Before LOHA writes the file, it resolves them into explicit final values. In other words, the saved file keeps the answer, not the shortcut you used while entering it.

Third, after a successful install, `/etc/loha/loha.conf` is rewritten into LOHA's standard format. Existing comments, custom keys, original layout, and historical shell-style syntax should not be treated as content that will be preserved.

The default installed layout includes:

- `/etc/loha/loha.conf`
- `/etc/loha/rules.conf`
- `/etc/loha/state.json`
- `/etc/loha/txn/`
- `/etc/loha/history/`
- `/usr/local/bin/loha`
- `/usr/local/libexec/loha/loader.sh`
- `/usr/local/lib/loha-port-forwarder/loha/`
- `/usr/local/share/loha/locales/*.toml`
- `/etc/systemd/system/loha.service`
- `/etc/sysctl.d/90-loha-forwarding.conf`
- `/etc/sysctl.d/90-loha-conntrack.conf` when needed
- `/etc/modprobe.d/loha-conntrack.conf` when needed
- `/run/loha/`

The extra files under `/etc/loha/state.json`, `/etc/loha/txn/`, and `/run/loha/` are LOHA-managed control-plane metadata. They exist so LOHA can keep desired state, staged transactions, runtime sync state, and recovery breadcrumbs consistent across config writes, reloads, rollback, install, and uninstall. They are not intended as a second user-facing config surface.

### Control-Plane Consistency and Concurrent Changes

LOHA is designed so that normal control-plane mutations do not rely on shell timing luck.

In practical terms:

- `loha.conf` and `rules.conf` are treated as one desired-state pair, not as two unrelated files
- mutating paths such as `config set`, alias and port changes, raw `rules.conf` edits, rollback, install, uninstall, and apply/reload all go through the same control-plane transaction path
- LOHA serializes those mutations with an internal exclusive lock; if another control-plane change is already in progress, a later caller should block briefly and then fail with a lock-conflict style error rather than partially interleaving writes
- raw `rules.conf` editing uses a staged copy and validation before commit, so a failed edit does not overwrite the live file pair

For operators and automation, the important takeaway is simple:

- treat `/etc/loha/state.json`, `/etc/loha/txn/`, and `/run/loha/` as LOHA-owned metadata, not as files to hand-edit
- use `loha config show --json` or `loha doctor` when you need to understand desired versus applied state, pending actions, or the last apply error
- if automation sees a lock-conflict result, treat it as a real control-plane contention signal and retry deliberately instead of assuming the change partially succeeded

### Uninstall and Upgrade

If you installed from the release bootstrap path and did not keep a local copy of the release archive, download and unpack the release archive again before using `./uninstall.sh`.

Uninstall:

```bash
sudo ./uninstall.sh
```

Run a safe non-interactive uninstall. This removes the installed LOHA payload but keeps `loha.conf`, `rules.conf`, `history/`, and system tuning files by default:

```bash
sudo ./uninstall.sh -y
```

Permanently delete all LOHA-managed files, including configuration, history snapshots, and kernel tuning files:

```bash
sudo ./uninstall.sh --purge
```

Run a non-interactive full purge:

```bash
sudo ./uninstall.sh -y --purge
```

Recommended upgrade path:

1. back up `/etc/loha/`
2. download and unpack the latest release archive, or update your local working tree
3. run the installer again
4. verify with `loha list` and `nft list table ip loha_port_forwarder`

Normal upgrades do not require a pre-uninstall. Re-running the installer is the expected path.

## 7 Daily Use

### Start With This Minimal Flow

If your goal is simply to expose one backend with one working forward, the safest sequence is:

1. create an alias for the backend
2. add the port rule
3. run `reload`
4. verify with `list`, `config show`, and `doctor`

Example:

```bash
sudo loha alias add VM_WEB 192.168.10.20
sudo loha port add tcp 80 VM_WEB
sudo loha port add tcp 443 VM_WEB
sudo loha port add tcp 8080 VM_WEB 80
sudo loha reload
sudo loha list
sudo loha config show
sudo loha doctor
```

For a whole range, this is also valid:

```bash
sudo loha port add tcp 5001+99 VM_WEB
```

If you want the exposed range and backend range to have different starting ports but the same length, this is also valid:

```bash
sudo loha port add tcp 8080+9 VM_WEB 18080+9
```

That exposes `8080-8089` and forwards to `18080-18089`. The two ranges only need equal length; they do not need the same base port.

### When To Use The Interactive Menu

For a first pass or occasional hands-on maintenance, start with:

```bash
sudo loha
```

The main menu is organized around a few core jobs:

- inspect current status and rules
- manage aliases
- add or delete port-forwards
- apply rules
- inspect the rendered `nft` rules
- open advanced settings
- change language

This path is a good fit when:

- you are learning LOHA for the first time
- your changes are low-frequency and manual
- you want to see the current state while making adjustments

Two details are worth knowing up front:

- raw `rules.conf` editing is treated as an advanced operation and requires explicit confirmation
- many advanced settings are available as standalone submenus, so you do not need to rerun the full wizard every time

### When To Use The CLI

The CLI is the better fit for:

- scripted maintenance
- batch rule changes
- Ansible or agent-driven workflows
- precise edits without entering the interactive menu

The most common day-to-day entry points are:

- `loha list` for a summary of saved config and mappings
- `loha config show` for core config, runtime binding, and system-integration state
- `loha doctor` for deeper diagnostics
- `loha config wizard` for interactive core-config changes
- `loha config rollback` for history restore

One distinction matters:

- `loha list` is a management summary, not a full live-diagnostics view
- `loha doctor` is the command that pulls together `systemd`, live `nft`, runtime binding, and system-feature state

### Remember These Rules For Core Config Changes

If you are changing core network behavior rather than port mappings, keep this set of rules in mind:

- `loha config wizard` is the safest interactive path
- `loha config set` is better when you already know the exact key you want to change
- after an `AUTH_MODE` change, run `loha reload --full` explicitly
- the advanced gateway settings inside `loha config wizard` write `loha.conf`, but do not immediately apply `rp_filter` or `conntrack`
- if you want `rp_filter` or `conntrack` applied immediately, use the dedicated commands or advanced-menu entry points

If you lean toward automation, make use of:

- `--json`
- `--check`
- `--dry-run`

They make it easier to keep validation, persistence, and apply as separate and predictable steps.

## 8 Rules File

LOHA stores rule data in:

```text
/etc/loha/rules.conf
```

It supports only two record types:

- `ALIAS`
- `PORT`

A typical example looks like this:

```text
# ALIAS  <name>  <ip>
ALIAS   VM_WEB  192.168.10.20
ALIAS   VM_DB   192.168.10.21

# PORT   <proto> <orig_port_spec> <dest_addr> <dest_port_spec>
PORT    tcp     8080        VM_WEB      80
PORT    tcp     3306        VM_DB       3306
PORT    tcp     5001-5100   VM_WEB      5001-5100
```

Editing `rules.conf` directly is useful when:

- you want to change many rules at once
- you already prefer a text-editor workflow
- you want to review a large rules change as one coherent edit

When editing manually, remember:

- `rules.conf` accepts canonical port syntax only, meaning a single port or a `start-end` range
- `+offset` shorthand such as `5001+99` is accepted only in CLI and TUI input and is normalized before being written to the file
- the interactive "edit rules file" path accepts `EDITOR` only as a single executable name or path

A conservative manual-edit flow is:

1. back up the file first
2. edit `/etc/loha/rules.conf` as root
3. run `sudo loha reload`
4. verify with `sudo loha list` and `sudo nft list table ip loha_port_forwarder`

If you do not want to edit the file by hand but need to delete multiple rules in one step, use `port prune`. For example:

```bash
sudo loha port prune --dest VM_WEB
sudo loha port prune --proto tcp --range 5001-5100
```

The key behavior is:

- at least one filter is required
- `--range` matches against the original listening-port range

Note:

- a rule is removed only if its entire original range falls within the filter
- if a range rule only partially overlaps the filter, LOHA keeps the rule unchanged instead of splitting it

For example, assume the current rules include:

```text
PORT    tcp     5001-5100   VM_WEB      5001-5100
PORT    tcp     5090-5120   VM_WEB      5090-5120
```

If you run:

```bash
sudo loha port prune --proto tcp --range 5001-5100
```

the result is:

- the first rule is removed, because its original listening range `5001-5100` falls entirely inside the filter range
- the second rule is kept, because it only overlaps part of the filter and still extends beyond it

LOHA does not split the second rule into smaller pieces such as "remove `5090-5100`, keep `5101-5120`." The behavior is all or nothing for each matching rule.

Additional note:

- partially overlapping listening-port ranges are rejected instead of being handed to nftables as competing `dnat_rules` map keys
- as a defense-in-depth measure, the renderer also refuses to submit conflicting duplicate `dnat_rules` keys even if an invalid internal rules object was constructed outside the normal parser path

For example, these two rules are not accepted as a valid ruleset:

```text
PORT    tcp     5001-5100   VM_WEB      5001-5100
PORT    tcp     5090-5120   VM_API      5090-5120
```

The second rule overlaps the first on `5090-5100` while pointing those ports at a different backend. LOHA rejects that overlap during normal rule validation, and the renderer also treats it as an invalid conflicting `dnat_rules` key shape if such an internal object were somehow constructed anyway.

## 9 Advanced Features

### Advanced NAT

If you need Hairpin NAT or WAN-to-WAN scenarios, you need to understand `rp_filter`.

`rp_filter` is Linux reverse-path filtering. A stricter default makes sense for ordinary gateway traffic, but it can become too conservative for some advanced NAT paths.

LOHA exposes four management modes:

- `system`
- `strict`
- `loose-scoped`
- `loose-global`

In practice:

- use `system` when you do not want LOHA managing `rp_filter`
- use `strict` when you want strict checks on the managed interfaces only
- use `loose-scoped` first when you need Hairpin NAT or WAN-to-WAN without loosening global behavior
- use `loose-global` only when you really need globally looser settings

The dedicated command and advanced-menu path rewrite the LOHA-managed sysctl file immediately and run `sysctl --system`. The advanced gateway settings inside `loha config wizard` only save the desired config; they do not apply it right away.

### How To Choose The Authorization Mode

For most users, the decision is straightforward:

- if you are not sure whether the environment already depends on complex `ct mark` behavior, stay on the default `ct mark` path
- if the environment already has heavy `ct mark` usage and you want LOHA isolated from it, use `ct label`

In the current implementation:

- static conflict checking starts by analyzing the existing `nft` rules on the system to see whether the value LOHA wants to use is already in use elsewhere
- the `ct mark` path adds more complete dynamic conflict detection on top of that and, when the environment allows it, also inspects runtime conntrack mark usage
- the `ct label` path is cleaner for isolation from existing mark schemes. It likewise checks existing `nft` rules for conflicting `ct label` usage, especially outside LOHA's own `loha_port_forwarder` table, but currently relies primarily on static conflict detection

Whichever path you choose, remember one thing: switching authorization mode is not a normal map-only hot update. It changes control-plane structure and should be treated like a full rebuild event.

### Conntrack Tuning

If the host is carrying large amounts of NAT traffic, `conntrack` often becomes the real capacity boundary.

You should check it first when:

- new connections fail under load
- the kernel reports `nf_conntrack: table full`
- the host has to carry large numbers of short-lived or highly concurrent forwarded flows

LOHA includes several useful capabilities here:

- current `conntrack` status
- conservative, standard, and high profiles
- auto-estimated and custom sizing
- clean handoff back to system management when you switch to `system`

As with `rp_filter`, the dedicated `conntrack` commands try to apply immediately, while the advanced gateway section of `loha config wizard` only writes the desired state into config.

### History and Rollback

When `ENABLE_CONFIG_HISTORY=on`, LOHA keeps history snapshots before changing `loha.conf` or `rules.conf`. By default:

- the history directory is `/etc/loha/history/`
- regular history keeps up to 5 recent snapshots
- rapid small changes within a 10-minute window preferentially reuse the newest slot
- the most recent successful rollback also keeps a separate rollback checkpoint that does not count against the regular 5-snapshot limit

This makes two kinds of work safer:

- frequent rule tuning
- undoing a recent bad change

If you want restore and apply in one step, use `loha config rollback ... --apply`.

### Other Gateway Level Options

LOHA also exposes several other gateway-oriented toggles, including:

- WAN-to-WAN forwarding
- TCP MSS Clamp
- `nftables` rule counter level
- strict internal source validation
- language switching and version display

Most of these are available as standalone advanced-menu entries, so you do not have to rerun the full wizard to change them.

## 10 Working Alongside Existing Firewalls

LOHA is not meant to take over every firewall responsibility on the host. Its role is to make port forwarding clearer and easier to manage.

For most LOHA hosts, one point should stay explicit: if the host is directly exposed to public traffic, the system firewall should still be enabled and deliberately configured. Using LOHA is not a reason to stop managing the host firewall seriously.

That means it often coexists with:

- Proxmox Firewall
- UFW
- Firewalld
- `nftables.service`
- `netfilter-persistent`
- legacy `iptables` or `ip6tables` services

Keep two operational reminders in mind:

- LOHA controlling its own exposed path does not automatically open cloud security groups, provider-side filters, or backend host firewalls
- when inbound traffic fails, you need to inspect LOHA, the host firewall, upstream filters, and the backend host itself

The installer tries to keep `loha.service` lightly coupled to the detected firewall owner:

- the baseline ordering anchor is `network.target`
- if the installer can identify the component that actually owns host firewall writes, it adds only an extra `After=`
- it does not add `Requires=` or `PartOf=` automatically

The detection priority is roughly:

1. follow the current host firewall backend on Proxmox VE
2. on other Linux hosts, detect a common firewall service based on active or enabled state
3. fall back to `network.target` if no known owner is found

The goal is not to turn LOHA into another firewall manager. The goal is simply to avoid having LOHA's rules loaded before an upstream firewall component rewrites the host state again.

## 11 Troubleshooting

### Dry Run Before Install

If you are about to do a first install or a reinstall, start with:

```bash
sudo ./install.sh --dry-run
```

It does not change the system, but it surfaces many environment-level problems early.

### Start With Summary Diagnostics And Live Rules

Most issues become much narrower once you look at these three views:

```bash
sudo loha list
sudo loha doctor
sudo nft list table ip loha_port_forwarder
```

They answer three different questions:

- what LOHA believes is saved
- what LOHA considers unhealthy in the current environment
- whether the kernel actually has the `loha_port_forwarder` table right now

### Check Inbound Failures In This Order

Recommended sequence:

1. `sudo loha doctor`
2. `sudo loha list`
3. `sudo nft list table ip loha_port_forwarder`
4. check cloud security groups or upstream filtering
5. check the backend host's default gateway
6. check the backend host's listening state and local firewall

If the issue shows up only in Hairpin NAT or WAN-to-WAN scenarios, also inspect the current `rp_filter` state:

```bash
sudo loha rpfilter status
sudo sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter
```

### Separate Reload Failures Into Layers

Common reasons for reload failure include:

- `rules.conf` syntax problems
- invalid alias references
- authorization-parameter conflicts
- invalid external binding, for example `LISTEN_IPS` not belonging to `PRIMARY_EXTERNAL_IF`
- broken `systemd` or `nft` runtime state

Start with:

```bash
sudo loha doctor
sudo /usr/local/libexec/loha/loader.sh check
```

If `loader.sh check` already fails, fix config or rule syntax first. If it passes but the service is still unhealthy, inspect:

```bash
sudo systemctl status loha --no-pager
sudo journalctl -u loha -b --no-pager
```

If you recently changed `AUTH_MODE` or another structural setting, it is often clearer to move straight to the explicit full path:

```bash
sudo loha reload --full
```

### High Concurrency Or Table Full

If the issue looks more like a capacity problem than a syntax problem, start here:

```bash
sudo loha conntrack status
```

When you are hitting `table full`, focus on:

- raising `nf_conntrack_max`
- adjusting buckets or hashsize
- reevaluating host memory against the expected connection model

## 12 FAQ

### FAQ 1 Does Authorize Then Clear On Miss Waste Performance

It adds some overhead, but that is usually not the important comparison.

`ct mark` and `ct label` are kernel conntrack metadata operations, so the per-flow cost is usually small. The real tradeoff is not "one extra metadata operation versus zero work." The real tradeoff is:

- a very small authorization-state write and check that keeps ownership of forwarding decisions explicit
- versus longer chains, more branching, and messier long-term maintenance

Without this model, the same complexity usually has to move somewhere else: longer match paths, more scattered conditions, or more decision-making buried deeper in the host firewall path. That difference may look small when the ruleset is tiny, but it becomes much more noticeable once the mapping set grows.

For a tool like LOHA that is meant to manage exposed mappings over time, that trade is usually worth it. The model is intentional: spend a little authorization-state work in exchange for clearer hit semantics, a steadier map-based forwarding path, and a control plane that stays easier to reason about.

### FAQ 2 How Should Pangolin And LOHA Be Split

If Pangolin currently runs directly on the PVE host and also carries a lot of basic ingress forwarding, a cleaner split is often:

1. install LOHA on the host
2. move Pangolin into its own VM
3. use LOHA to forward `80/tcp`, `443/tcp`, `51820/udp`, and `21820/udp` to that Pangolin VM
4. let Pangolin stay focused on web proxying, auth, policy, and tunnel-style access

The reason is simple:

- LOHA is better suited to host-side L3 and L4 forwarding control
- Pangolin is better suited to application-layer ingress behavior
- separating those roles usually gives you cleaner boundaries and easier maintenance

The gain is not only performance. The bigger win is cleaner responsibility split: the host handles public ingress, basic NAT, and port forwarding, while the Pangolin VM handles sites, certificates, identity, access policy, and tunnel features.

If some services do not need Pangolin's application-layer features at all, those TCP or UDP ports can also be forwarded directly by LOHA to the target backend instead of forcing everything through a user-space proxy on the host.

### FAQ 3 What If The Upstream Firewall Backend Changes Later

For example, on Proxmox VE, enabling `nftables: 1` can move the host firewall backend from `pve-firewall.service` to `proxmox-firewall.service`.

At that point, three common maintenance paths are:

1. edit `/etc/systemd/system/loha.service` manually, then run `systemctl daemon-reload`
2. rerun `sudo ./install.sh --non-interactive`
3. rerun `sudo ./install.sh` and accept the saved defaults

The latter two let the installer recalculate the correct `After=` target for the current environment.

### FAQ 4 What Usually Causes rules.conf Write Failures

Most of the time, it is a permissions issue rather than a rule-syntax issue.

Commands that add aliases, change port rules, run `reload`, or inspect runtime state normally need to be run through an account with `sudo`, for example:

```bash
sudo loha alias add VM_WEB 192.168.10.20
sudo loha port add tcp 8080 VM_WEB 80
sudo loha reload
```

`loha version` is an exception, but it should not be treated as evidence that most management commands are also non-root-safe.

### FAQ 5 Is systemd Required In The Current Release

Within the current implementation and documented boundary, yes.

LOHA's data plane is still the kernel `nftables` ruleset rather than a resident user-space forwarder, but the installer, service management, reload path, and `doctor` output are all designed around a `systemd` workflow today.

## 13 Command Reference

Most commands require root privileges. `loha version` is the main exception.

### Reading The Command Forms

- `<...>` means a required argument.
- `[...]` means an optional argument.
- command names, flags, config keys, paths, and other literal tokens stay in their real CLI form.
- when a placeholder is not self-explanatory, a short note appears below the command block.

### Common Commands At A Glance

```bash
sudo loha
sudo loha list
sudo loha config show
sudo loha doctor

sudo loha alias add VM_WEB 192.168.10.20
sudo loha port add tcp 8080 VM_WEB 80
sudo loha rules render
sudo loha reload
sudo loha reload --full
```

### Aliases And Port Rules

```bash
sudo loha alias add <name> <ip>
sudo loha alias rm <name>

sudo loha port add [--force] <tcp|udp> <orig_port_spec> <dest_addr> [dest_port_spec]
sudo loha port rm <tcp|udp> <orig_port_spec>
sudo loha port prune [--dest <alias|ip>] [--proto <tcp|udp>] [--range <orig_port_spec>]
```

Notes:

- aliases must start with `HOST_` or `VM_`
- `dest_addr` can be an alias or an IPv4 address
- `orig_port_spec` and `dest_port_spec` can be single ports or equal-length ranges
- `+offset` forms such as `5001+99` are accepted only in CLI and TUI input
- `port add --force` skips local listener-conflict checks

Parameter notes:

- `orig_port_spec` is the external listening port or port range.
- `dest_addr` is the backend target, either an alias or a direct IPv4 address.
- `dest_port_spec` is the backend destination port or range; when omitted, LOHA reuses the external port value.

Examples:

```bash
sudo loha port add tcp 8080 VM_WEB 80
sudo loha port add tcp 8001+50 VM_WEB 9001+50
sudo loha port prune --dest VM_WEB --proto tcp --range 5001-5100
```

### Render, Reload, And Diagnose

```bash
sudo loha rules render
sudo loha list
sudo loha reload
sudo loha reload --full
sudo loha doctor
loha version
```

Notes:

- `loha rules render` prints the current full rendered `nft` ruleset without applying it
- it renders from the current `loha.conf` and `rules.conf`; it does not read the live kernel `nft` table
- use `sudo nft list table ip loha_port_forwarder` when you want the active kernel state
- `loha list` shows saved config and mapping summary, not full live diagnostics
- `loha doctor` pulls together `systemd`, live `nft`, listener conflict checks, runtime binding, and system-feature state

### Config And Rollback

```bash
sudo loha config show
sudo loha config get <KEY>
sudo loha config set <KEY> <VALUE>
sudo loha config normalize
sudo loha config history
sudo loha config history show
sudo loha config history status
sudo loha config history enable
sudo loha config history disable
sudo loha config rollback [latest|<1-5>] [--apply]
sudo loha config wizard
```

Notes:

- `config show` includes core config plus runtime binding and system-integration state
- `config set AUTH_MODE ...` writes config only and does not implicitly rebuild the control plane; follow it with `loha reload --full`
- `config normalize` rewrites the current canonical config and materializes input shortcuts
- `config wizard` is the safer interactive path for core-config changes

Parameter notes:

- in `config rollback [latest|<1-5>] [--apply]`, `latest` means the most recent available rollback target
- `<1-5>` selects a snapshot by index
- `--apply` restores the files and then applies the runtime change immediately; without it, only the files are restored

### rp_filter And Conntrack

```bash
sudo loha rpfilter status
sudo loha rpfilter set <system|strict|loose-scoped|loose-global>

sudo loha conntrack status
sudo loha conntrack profile <conservative|standard|high>
sudo loha conntrack auto <peak> [memory_percent]
sudo loha conntrack set <max> [memory_percent]
sudo loha conntrack system
```

Notes:

- these commands let you manage system-integration state directly without rerunning the full config wizard
- the dedicated `rpfilter` and `conntrack` commands go through their own apply paths immediately
- `conntrack system` hands conntrack management back to the system

Parameter notes:

- `rpfilter set <system|strict|loose-scoped|loose-global>` selects how LOHA should manage `rp_filter`
- `conntrack profile <conservative|standard|high>` applies a built-in profile
- `conntrack auto <peak> [memory_percent]` uses an estimated peak concurrent connection count plus an optional memory percentage
- `conntrack set <max> [memory_percent]` sets an explicit maximum concurrent connection count plus an optional memory percentage

Examples:

```bash
sudo loha conntrack auto 300000 40
sudo loha conntrack set 500000 50
```

### Automation Friendly Capabilities

The following are especially useful for scripts, orchestration tools, and agents:

- `--json` on commands such as `list`, `rules render`, `doctor`, `config show`, `config set`, `reload`, `config history status/show`, `config rollback`, alias and port writes, `rpfilter`, and `conntrack`
- `--check` or `--dry-run` on commands that would otherwise modify `loha.conf`, `rules.conf`, or LOHA-managed system-tuning files
- stable result categories, error categories, and exit codes for machine-side handling
- explicit lock-conflict reporting when another control-plane mutation already holds the exclusive writer path

`--check` validates the request and previews the target result, but does not actually write files, create history snapshots, or run `sysctl --system`.

For automation, the most useful control-plane fields now live in `config show --json` and the dedicated JSON endpoints:

- `config show --json` exposes `control_plane.desired_revision`, `applied_revision`, `runtime_synced`, `pending_actions`, and the last apply error
- `reload --json` reports requested and effective apply mode plus current revision state
- `config history status/show --json` reports snapshot state without scraping human-facing output
- `config rollback --json` reports what was restored and whether runtime still has pending work such as `reload`

## 14 Docs Testing Translation

If you want to go deeper, these are the most useful follow-on entry points:

- project overview and quick start: [README.md](./README.md)
- Chinese manual: [MANUAL_zh_CN.md](./MANUAL_zh_CN.md)
- terminology and translation baseline: [docs/translation-baseline.md](./docs/translation-baseline.md)
- config model and canonical contract: [docs/canonical-config-model.md](./docs/canonical-config-model.md) and [docs/config-file-contract.md](./docs/config-file-contract.md)
- installer and interaction behavior: [docs/installer-flow.md](./docs/installer-flow.md), [docs/interaction-contract.md](./docs/interaction-contract.md), and [docs/summary-confirmation-design.md](./docs/summary-confirmation-design.md)
- runtime boundary and rendering behavior: [docs/multi-external-boundary.md](./docs/multi-external-boundary.md) and [docs/nft-renderer-architecture.md](./docs/nft-renderer-architecture.md)
- validation baseline: [docs/validation-matrix.md](./docs/validation-matrix.md)

The main validation entry points in the current repository are:

- `scripts/run_tests.sh`
- `scripts/run_smoke.sh`

Translation-related files live in:

- the repository: `locales/*.toml`
- the installed system: `/usr/local/share/loha/locales/*.toml`

LOHA is already translation-ready. Whether you want to fix wording, add another language, or improve the README and MANUAL, those contributions are welcome.
