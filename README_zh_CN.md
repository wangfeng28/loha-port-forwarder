# LOHA Port Forwarder

[English](./README.md) | 简体中文

> 给“公网流量先到宿主机、再转给后端服务”的场景，一套更清楚、更可维护的 Linux 原生端口转发控制层。

LOHA Port Forwarder（简称 LOHA）是一个基于 `nftables` 的 Linux 端口转发 / NAT 控制层。它面向这样一类部署：公网流量直接落到宿主机，再转发给 VM、容器或内部主机。LOHA 的目标不是再造一台独立防火墙设备，而是在宿主机上把这些转发关系管理得更清楚、更可审查，也更容易持续维护。

如果你想保留 Linux 原生网络栈的透明度，又不想为了管理端口转发额外部署一台防火墙 VM，LOHA 值得考虑。它提供一条完整但不过度复杂的路径：安装、配置、`reload`、回退，以及日常运维。同时，CLI 也提供更适合自动化的 JSON 输出、稳定结果/错误分类，以及 `--check` / `--dry-run` 演练路径，便于接入 Ansible、脚本和 AI Agent。更深入的原理、完整 CLI/TUI 参考、排障和高级边界，请看 [MANUAL_zh_CN.md](./MANUAL_zh_CN.md)。

## 它解决什么问题

- 很多 Proxmox VE / 自建 Linux 宿主机本来就是公网入口，真正需要的只是把少数端口稳定地转给后端服务。
- 纯手写 `nftables` / `iptables` 规则在规模变大后，越来越难审查、修改和回退。
- 为了管理这些转发再额外部署一台防火墙 VM，能解决一部分问题，但也会引入新的资源开销、运维复杂度和故障域。
- LOHA 适合的是中间地带：继续使用 Linux 宿主机自身的网络栈，但把端口转发收敛成更清晰的工作流。

## LOHA 这个名字代表什么

LOHA 不是一个装饰性名称，而是这个项目的设计取向：

- **L**ightweight（轻量）：不需要额外的防火墙 VM，也不依赖常驻用户态转发进程；规则进入内核后，控制脚本即可退出。
- **O**bservable（可观测）：配置、规则、运行时状态，以及控制逻辑本身都尽量保持可读、可审查、可排障；项目主要由 Python、shell、TOML 这类文本资产构成，而不是一团难以追踪的黑盒二进制。
- **H**ost-native（宿主机原生）：直接运行在 Linux 宿主机上，复用 nftables、systemd、sysctl 和纯文本配置，不额外引入另一套设备式控制层。
- **A**uthorization-driven（授权驱动）：转发路径围绕明确的授权状态（ct mark / ct label）组织，而不是只堆一层裸 DNAT 规则。

这四点就是 LOHA 名称的由来，也是它和“单纯写几条 NAT 规则”之间最重要的区别。

## 为什么它适合当前这类宿主机场景

LOHA 特别适合下面这类主机场景：

- 对外暴露入口已经在 Linux 宿主机上，而不是在独立防火墙设备上。
- 你需要把公网入口转给 VM、容器或内部主机，但仍想保留宿主机自己的网络透明度和可控性。
- 你希望配置是纯文本、可备份、可脚本化、可审查的。
- 你既想让它适合人工维护，也想让它更容易被 Ansible、编排脚本或 AI Agent 调用。
- 你想要的不只是“规则能生效”，还包括一条清楚的安装、配置、`reload`、回退和日常维护路径。

## 当前定位与边界

LOHA 当前的定位很明确：

- 它是基于 `nftables` 的 Linux 端口转发 / NAT 控制层，不是完整防火墙发行版。
- 典型场景是公网流量直接落到宿主机，再转发给 VM、容器或内部主机。
- 当前主线范围聚焦 IPv4、`systemd`，以及“一个主外部接口 + 一个或多个对外暴露用外部 IPv4 地址”的常见模型。
- 它不以完整多外部接口对称回程、复杂路由编排、集中式多节点策略管理为当前目标。
- 如果你只需要极少量一次性转发，并且已经愿意长期手工维护底层规则，LOHA 也未必是必要抽象。

## 运行基线

- 当前文档覆盖的最低运行基线：Linux kernel 5.6+、`systemd`、`Python` 3.8+、`nftables` 0.9.4+。
- 从代码实现带来的直接收益来看，更推荐 `Python` 3.11+ 和 `nftables` 1.0.7+。
- 对 Linux kernel 和 `systemd`，当前代码并没有高于最低基线的固定版本要求；更合适的建议是使用发行版当前仍受支持的 LTS / 稳定版本。

## 快速开始

1. 安装

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/installer.sh | sudo sh
```

如果你想先查看安装计划而不改系统，可以先运行：

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/installer.sh | sudo sh -s -- --dry-run
```


如果你更希望先完整检查安装文件，再决定是否执行，请按 [MANUAL_zh_CN.md](./MANUAL_zh_CN.md) 里的手工下载、校验和 provenance 校验流程操作。

2. 做最基本的安装后检查

```bash
sudo loha doctor
sudo systemctl status loha --no-pager
sudo nft list table ip loha_port_forwarder
```

3. 添加一条最小可工作的转发规则

```bash
sudo loha alias add VM_WEB 192.168.10.20
sudo loha port add tcp 80 VM_WEB
sudo loha reload
```

4. 查看当前配置并预览渲染结果

```bash
sudo loha list
sudo loha config show
sudo loha rules render
```

再演示一个便捷的命令：

```bash
sudo loha port add tcp 8080+9 VM_WEB 18080+9
```

它表示对外暴露 `8080-8089`，并转发到 `18080-18089`。外部端口范围和目标端口范围只要求长度一致，起始端口不需要相同。

## 日常使用方式概览

- `sudo loha`：交互式菜单，适合第一次上手、偶尔调整和手动维护。
- CLI：适合脚本和自动化，常见入口包括 `alias`、`port`、`rules render`、`reload`、`config`、`doctor`、`config history` 和 `config rollback`；`--json`、稳定结果/错误分类，以及 `--check` / `--dry-run` 也更方便接入 Ansible 和 AI Agent。控制面写入会串行化处理，所以并发修改要么形成一致结果，要么明确返回锁冲突，而不是悄悄交错覆盖。
- 配置文件：核心配置保存在 `/etc/loha/loha.conf`，规则保存在 `/etc/loha/rules.conf`。
- 变更路径：日常增删映射通常使用 `reload`；LOHA 会优先尝试热更新，但如果控制面骨架已经变化，也可能把这次 apply 升级成完整重建。像 `AUTH_MODE` 这类结构性改动，如果你希望“完整重建”这件事显式发生，仍应直接使用 `reload --full`。

## 全面了解与进阶使用

[MANUAL_zh_CN.md](./MANUAL_zh_CN.md) 提供完整的工作原理、安装与卸载、CLI 命令、TUI 操作、高级功能、排错建议和常见问题说明。你可以从头完整阅读，逐步建立对 LOHA 的整体认识，也可以在需要时按章节跳读。

## 多语言支持

i18n 是 LOHA 的原生能力。如果你有具体语言需求，欢迎提出；如果你愿意一起补充翻译，也欢迎直接参考 `locales/*.toml` 提交你的版本。

## 许可证

本项目采用 [MIT License](./LICENSE) 授权。
