# LOHA Port Forwarder

English | [简体中文](./README_zh_CN.md)

> A cleaner, more maintainable host-native way to expose services when public traffic lands on the Linux host first.

LOHA Port Forwarder, or LOHA, is an `nftables`-based port-forwarding and NAT control layer for Linux hosts. It is built for a common self-hosting and homelab layout: public traffic reaches the host directly, then needs to be forwarded to a VM, container, or internal machine. LOHA does not ask you to insert a separate firewall VM just to manage those mappings. It keeps that path on the host, readable, and operationally manageable.

If you want Linux-native network transparency without living inside a hand-maintained ruleset, LOHA is worth a look. It gives you a practical workflow for installation, configuration, `reload`, rollback, and day-to-day operations. The CLI also exposes locale-neutral JSON output, stable result/error categories, and `--check` / `--dry-run` preview paths that make it easier to drive from Ansible, scripts, and AI agents. For deeper mechanics, full CLI/TUI reference, troubleshooting, and current product boundaries, see [MANUAL.md](./MANUAL.md).

## The Problem It Solves

- Many Proxmox VE and self-hosted Linux nodes already sit at the public edge; what they really need is a clean way to forward selected ports to backend services.
- Hand-maintained `nftables` / `iptables` rules are fine at first, but get harder to review, change, and roll back as the mapping set grows.
- Adding a separate firewall VM can solve part of the management problem, but it also adds resource overhead, more operational surface area, and another failure domain.
- LOHA is for the middle ground: keep the Linux host's own networking stack, but manage port exposure through a workflow that is easier to understand and maintain.

## What LOHA Means

LOHA is not just a name. It summarizes the project's design priorities:

- **L**ightweight: no extra firewall VM and no resident user-space forwarding daemon; once the rules are loaded, the control script can exit.
- **O**bservable: you can see the saved config, the rendered rules, and the current runtime state, which makes change review and troubleshooting much easier.
- **H**ost-native: LOHA does not wrap Linux in a second appliance layer. It works directly with the host's own `nftables`, `systemd`, `sysctl`, and plain-text configuration.
- **A**uthorization-driven: forwarding is not treated as raw `DNAT` alone. LOHA organizes that path around explicit authorization state (`ct mark` / `ct label`).

That is where the name comes from, and it is also the clearest summary of how LOHA is meant to behave.

## Why It Fits This Kind of Host Setup

LOHA is a strong fit when:

- the exposure edge already lives on the Linux host instead of a separate firewall appliance;
- you need to forward public traffic to VMs, containers, or internal hosts while keeping host-side visibility and control;
- you want plain-text configuration that is easy to back up, script, and review;
- you want something that works for human operators but is also easier to drive from Ansible, orchestration scripts, or AI agents;
- you need more than rules that merely "work" and want a clear path for install, configuration, `reload`, rollback, and routine operations.

## Current Scope and Boundary

LOHA's current product boundary is intentionally narrow:

- It is an `nftables`-based Linux port-forwarding and NAT control layer, not a full firewall distribution.
- The typical scenario is public traffic landing on the host and being forwarded to VMs, containers, or internal hosts.
- The current mainline scope focuses on IPv4, `systemd`, and the common model of one primary external interface plus one or more external IPv4 addresses used for exposure on that interface.
- It is not currently aimed at full multi-external symmetric return-path behavior, complex routing orchestration, or centralized multi-node policy management.
- If you only need a tiny number of one-off forwards and are already comfortable maintaining the underlying rules by hand, LOHA may be more structure than you need.

## Runtime Baseline

- Minimum documented runtime baseline: Linux kernel 5.6+, `systemd`, `Python` 3.8+, and `nftables` 0.9.4+.
- Recommended versions with direct code-level benefit: `Python` 3.11+ and `nftables` 1.0.7+.
- For Linux kernel and `systemd`, LOHA currently does not require a higher fixed version beyond the documented baseline; prefer a currently vendor-supported LTS release on your distribution.

## Quick Start

1. Install

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/installer.sh | sudo sh
```

If you want to inspect the install plan without changing the system first:

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/installer.sh | sudo sh -s -- --dry-run
```

If you prefer a fully inspectable path, download and verify the release archive manually before running the installer. The step-by-step archive flow, checksum verification, and provenance verification examples are documented in [MANUAL.md](./MANUAL.md).

2. Run the minimum post-install checks

```bash
sudo loha doctor
sudo systemctl status loha --no-pager
sudo nft list table ip loha_port_forwarder
```

3. Add one minimal working port forward

```bash
sudo loha alias add VM_WEB 192.168.10.20
sudo loha port add tcp 80 VM_WEB
sudo loha reload
```

4. Inspect the saved config and preview the rendered result

```bash
sudo loha list
sudo loha config show
sudo loha rules render
```

One slightly more advanced example is worth knowing:

```bash
sudo loha port add tcp 8080+9 VM_WEB 18080+9
```

That exposes `8080-8089` and forwards to `18080-18089`. The external and destination ranges only need to have the same length; they do not need to start at the same port.

## Daily Use at a Glance

- `sudo loha`: an interactive menu for first-time setup, occasional changes, and hands-on maintenance.
- CLI: suited for scripts and automation, with common entry points including `alias`, `port`, `rules render`, `reload`, `config`, `doctor`, `config history`, and `config rollback`; `--json`, stable result/error categories, and `--check` / `--dry-run` also make it easier to use from Ansible and AI agents. Control-plane writes are serialized, so concurrent mutations should resolve as a coherent update or a lock conflict rather than silently interleaving.
- Config files: core config lives in `/etc/loha/loha.conf`, and rules live in `/etc/loha/rules.conf`.
- Change path: routine mapping changes usually use `reload`; LOHA prefers hot update there, but may still promote that apply to a full rebuild if the control-plane skeleton changed. Structural changes such as `AUTH_MODE` should still use `reload --full` when you want the full rebuild to remain explicit.

## Learn More and Go Further

[MANUAL.md](./MANUAL.md) covers the full operating model, installation and uninstall behavior, CLI commands, TUI workflows, advanced features, troubleshooting guidance, and FAQ. You can read it straight through to build a complete mental model of LOHA, or jump to the sections you need.

## Multi-language Support

i18n is a native capability in LOHA. If you need a specific language version, let us know; if you want to help, start from `locales/*.toml` and contribute your translation.

## License

This project is released under the [MIT License](./LICENSE).
