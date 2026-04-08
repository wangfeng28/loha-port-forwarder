# LOHA Port Forwarder 完整手册

[English](./MANUAL.md) | 简体中文

这份手册面向愿意把 LOHA 真正用明白的用户。README 负责帮助你快速判断项目定位与是否值得尝试；MANUAL 负责把整件事讲完整：LOHA 是什么，它为什么适合某些宿主机场景，它怎么工作，怎么安装，日常如何维护，哪些地方属于高级能力，哪里是当前边界，出了问题先从哪里查。

如果你只想快速上手，请先看 [README_zh_CN.md](./README_zh_CN.md)。

## 目录

- [术语说明](#术语说明)
- [1 导言](#1-导言)
- [2 LOHA 是什么与适合对象](#2-loha-是什么与适合对象)
- [3 为什么很多宿主机更适合 LOHA](#3-为什么很多宿主机更适合-loha)
- [4 LOHA 的工作方式](#4-loha-的工作方式)
- [5 环境要求与边界](#5-环境要求与边界)
- [6 安装 卸载 升级](#6-安装-卸载-升级)
- [7 日常使用](#7-日常使用)
- [8 规则文件](#8-规则文件)
- [9 高级功能](#9-高级功能)
- [10 与现有防火墙共存](#10-与现有防火墙共存)
- [11 排错建议](#11-排错建议)
- [12 常见问题](#12-常见问题)
- [13 命令参考](#13-命令参考)
- [14 文档 测试 翻译](#14-文档-测试-翻译)

## 术语说明

- `external` 指 LOHA 视角下的外部侧，也就是受保护内部网络之外的那一侧。它不一定等同于真正可全球路由的公网。
- `internal` 指 LOHA 视角下的内部侧，也就是受保护的接口和内部网络。
- `exposed` 指 LOHA 明确对外暴露的服务或外部 IPv4 地址。
- “授权模式”指 LOHA 在内核里用来区分“允许转发的流量”和“其它流量”的授权状态机制。`ct mark` 和 `ct label` 是转发授权机制，不是登录认证系统。
- “热更新”指尽量沿用当前控制面，仅更新映射数据；“完整重建”指重建完整 ruleset 和控制状态。

## 1 导言

如果你是第一次认真读 LOHA，推荐按这条顺序往下读：

1. 先看第 2 到第 5 章，建立心智模型。
2. 再看第 6 到第 9 章，掌握安装、日常使用和高级能力。
3. 需要查命令时，最后再去第 13 章。

本手册刻意把详细命令清单放到后面。正文优先回答这些问题：

- LOHA 到底是什么。
- 为什么有些宿主机特别适合它。
- 它怎样把配置变成内核里的转发规则。
- 日常维护时哪些操作是常规路径，哪些操作属于更重的变更。

如果你已经熟悉 LOHA，只是回来查某个命令、排错路径或高级设置，可以直接跳到对应章节。

## 2 LOHA 是什么与适合对象

LOHA 是一个基于 `nftables` 的 Linux 端口转发与 NAT 控制层。它面向一种很常见的宿主机现实：公网流量先落到 Linux 宿主机，再转发给 VM、容器或内部主机。LOHA 不去把宿主机包装成另一台防火墙 appliance，而是把这条宿主机原生路径整理成更清楚、可审查、可维护的工作流。

你可以把它理解为三层能力的组合：

- 用 canonical `loha.conf` 保存核心网络语义。
- 用 `rules.conf` 保存别名和端口映射。
- 用 LOHA 的 loader 和 renderer 把这些内容转换成稳定的 `nftables` 规则，并加载到内核。

LOHA 这个名字对应四个设计取向：

- **L**ightweight：控制面只在安装、配置、`reload`、回退等时刻介入；规则加载完成后，数据面仍由内核中的 `nftables` 直接承担，不需要额外的常驻用户态转发进程。
- **O**bservable：核心配置、端口规则、渲染结果、运行时绑定状态和诊断输出都有明确落点，便于审查变更、比对现状和排错。
- **H**ost-native：LOHA 不额外引入一套设备式防火墙抽象，而是直接复用 Linux 宿主机已有的 `nftables`、`systemd`、`sysctl`、纯文本配置和服务生命周期。
- **A**uthorization-driven：转发放行不是依赖一串彼此松散的裸 `DNAT` 规则，而是围绕显式的授权状态（`ct mark` / `ct label`）组织，使授权、放行、miss cleanup 和保护范围判断沿同一条控制语义收敛。

LOHA 特别适合这些情况：

- 公网入口已经在 Linux 宿主机上，而不是在独立防火墙设备上。
- 你需要把少量到中等规模的外部端口稳定转给 VM、容器或内部主机。
- 你想保留宿主机原生网络栈的透明度，但不想长期手写和维护不断增长的规则集。
- 你希望配置是纯文本、可备份、可脚本化、可审查的。
- 你希望同一套工具既适合人工维护，也适合脚本、Ansible 或 Agent 调用。

LOHA 不适合替代这些东西：

- 完整防火墙发行版。
- 多节点集中式策略系统。
- 复杂多 WAN 路由编排、对称回程保证、WAN 级高可用与负载均衡。
- 当前文档范围之外的非 `systemd` 主机工作流。

## 3 为什么很多宿主机更适合 LOHA

在很多自建环境里，真正的问题不是“要不要有防火墙”，而是“公网入口已经在宿主机上了，怎样把这部分转发管理得更像一个长期可维护的系统”。

传统上常见两条路：

- 直接手写 `nftables` 或 `iptables`。
- 在前面再套一层 pfSense、OPNsense 或其它软路由 VM。

这两条路都能工作，但各自会把成本带到不同地方。

手写规则的问题通常不是第一天，而是几个月后：

- 规则越来越多时，变更审查会变难。
- 规则顺序、覆盖关系和历史遗留会越来越难靠肉眼判断。
- 回滚往往依赖手工编辑、命令历史或临时记忆，出错概率会上升。

额外防火墙 VM 的问题则是另一种：

- 你获得了更强的控制点，也额外引入了一层 appliance。
- 它会占用宿主机资源，增加运维面和故障域。
- 对某些场景来说，这个成本是值得的；但对另一些场景，它只是为了管理少量端口转发而过度建设。

LOHA 适合的就是中间地带：

- 公网入口已经在宿主机。
- 你主要想把外部端口清楚地转给后端。
- 你仍然希望规则、配置和运行路径保持 Linux 原生、可见和可控。

这也是为什么很多 Proxmox VE 宿主机、自建 Linux 网关和 Homelab 边缘节点，会比“专门再起一台防火墙 VM”更适合先考虑 LOHA。

## 4 LOHA 的工作方式

### 两份核心文件

LOHA 的日常管理围绕两份文件展开：

- `/etc/loha/loha.conf` 保存核心配置，也就是外部接口、对外暴露用外部 IPv4 地址、内部网络、保护范围、默认出口 NAT、授权模式和系统集成设置。
- `/etc/loha/rules.conf` 保存别名和端口映射，也就是“把哪个协议和端口转给哪个后端”。

两者分工很明确：

- `loha.conf` 决定整体拓扑和控制面行为。
- `rules.conf` 决定具体有哪些暴露规则。

这也是为什么“改几条端口”和“切换授权模式”在 LOHA 里是不同级别的变更。

### 授权模式如何工作

LOHA 的授权模式目前有两条路径：

- `ct mark` 模式。
- `ct label` 模式。

两者的目标相同，都是让 LOHA 在内核里明确区分“这条流量是命中过有效映射、可以沿授权路径继续走的”与“这条流量不应被放行”。

默认 `ct mark` 模式下，大致逻辑是：

1. 先给候选流量写入专用授权 bit。
2. 再做映射查表。
3. 命中映射则保留授权路径。
4. 未命中则显式清掉授权 bit。

这套做法的重点不是“多做一步标记”，而是把授权资格和真实映射命中绑在一起。这样在 `forward` 链上，LOHA 可以用更清楚的条件判断来决定放行或阻断。

`ct label` 模式的设计目标相同，只是把授权状态放在 `ct label`，以减少与现有 `ct mark` 规划的耦合。它不是比 `ct mark` “更高级”，而是更适合那些已经大量使用 `ct mark` 的环境。

### 规则如何进入内核

LOHA 的主路径可以概括成四步：

1. 读取 canonical `loha.conf` 和 `rules.conf`。
2. 校验运行时绑定和配置边界。
3. 把端口映射整理成 `nftables map`、`set`、`define` 和固定链结构。
4. 把结果加载到内核，并记录控制状态。

这里最重要的理解点有两个。

第一，LOHA 不靠“一个端口一条独立 NAT 规则”的长链来组织映射，而是把映射收敛成 `map` 查表。这让规则数量增长时，维护体验不会线性恶化。

第二，LOHA 不是只做一层裸 `DNAT`。它把“允许哪些流量继续走转发路径”也纳入同一个模型里，因此转发、授权和保护范围是一起设计的。

### 为什么不需要常驻用户态进程

LOHA 的长期数据面在内核里，不在用户态 daemon 里。

当前 `loha.service` 是 `oneshot` 风格的控制面入口。它的职责是生成、校验、加载或更新规则；规则一旦进入内核，真正长期工作的就是 `nftables` 规则本身，而不是一个持续处理流量的用户态转发进程。

这带来两个直接结果：

- 宿主机仍然走 Linux 原生转发路径。
- LOHA 的常驻开销集中在规则和系统集成本身，而不是额外的用户态流量代理。

### 热更新与完整重建

日常增删端口规则时，你通常执行：

```bash
sudo loha reload
```

这条命令的语义是：

- 要求 `loha.service` 当前已经是 active。
- 走 `systemd reload` 路径。
- 让 loader 先尝试按热更新方式处理。

如果新的渲染结果和当前控制状态仍兼容，LOHA 只会更新 map 和 set 这类映射数据，尽量不重建整张表。

如果 loader 发现控制状态已经不匹配，例如你改了会影响控制面骨架的核心行为，它会在内部把这次 `reload` 升级成完整 apply。也就是说，`reload` 的入口语义仍然是“已有服务上的常规重载”，但 loader 会根据控制状态决定能不能保持轻量路径。

这意味着 `reload` 和 `reload --full` 仍然有不同的入口语义，但它们并不是“永远对应两种完全不同的内核动作”。普通 `reload` 会先判断热更新是否仍然安全；只有当控制面骨架没变时，它才会停留在更轻的路径上。

显式完整重建则使用：

```bash
sudo loha reload --full
```

它更适合这些情况：

- `loha.service` 当前不在运行。
- 你明确想重建整个控制面。
- 你刚改的是 `AUTH_MODE` 这类结构性配置。
- 你希望把“配置已写入”和“完整重建已执行”这两件事明确分开。

要特别注意一点：

- 普通 `reload` 不会替你处理“服务已经停掉但我还想顺手重启”的场景。
- 当服务 inactive 或 failed 时，应该直接使用 `reload --full`。

## 5 环境要求与边界

当前文档覆盖的运行基线是：

- Proxmox VE 7+、Debian 11+、Ubuntu 20.04+、RHEL 9+。
- Linux kernel 5.6+。
- `nftables` 0.9.4+。
- `Python` 3.8+。
- `systemd`。

这里还有一个兼容性细节需要明确说明：完整 apply 不再假设所有受支持的 `nft` 解析器都接受同一种 table-reset 语法。LOHA 会在运行时探测能力，并在重建受管 table 时选择兼容的 reset 命令，而不是把 `destroy table ...` 当成唯一固定路径。

常见运行时依赖包括：

- `python3`
- `nft`
- `ip`
- `sysctl`
- `systemctl`

大多数管理命令需要 root 权限；`loha version` 是最明显的例外。

当前正式支持边界应理解为：

- 以 IPv4 为主。
- 以 `systemd` 工作流为前提。
- 主线产品边界是一个主外部接口，加上该接口上的一个或多个对外暴露用外部 IPv4 地址。
- `DEFAULT_SNAT_IP` 是显式主值，不靠“列表第一项”隐式猜测。

可以把当前支持面概括成：

- `single-external + multi-listen-ip`

而不是：

- 真正的 `multi-external`

当前版本不承诺这些能力：

- 多外部接口完整支持。
- 从哪个 WAN 进就从哪个 WAN 回的对称回程模型。
- 多 WAN 高可用或负载均衡。
- 复杂策略路由编排。
- 完整替代宿主机现有防火墙体系。

如果你的场景核心就是这些能力，LOHA 不应该被当成主角。

## 6 安装 卸载 升级

### 交互安装

首先从 GitHub Releases 获取安装文件。最快的路径是使用 release bootstrap 安装器：

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/installer.sh | sudo sh
```

如果你想先看安装计划而不改系统，可以这样执行：

```bash
curl -fsSL https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/installer.sh | sudo sh -s -- --dry-run
```

如果当前命令运行环境没有可交互终端，请改用 `--non-interactive` 非交互流程。

这个 bootstrap 脚本会从同一个 GitHub Release 下载 `loha-port-forwarder.tar.gz` 和 `loha-port-forwarder.tar.gz.sha256`，先做校验和校验，再把压缩包解压到临时工作目录，最后执行其中自带的 `./install.sh`。

如果你更希望在执行前完整检查 release 文件，可以手工下载并校验压缩包：

```bash
curl -fsSLO https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/loha-port-forwarder.tar.gz
curl -fsSLO https://github.com/wangfeng28/loha-port-forwarder/releases/latest/download/loha-port-forwarder.tar.gz.sha256
sha256sum -c loha-port-forwarder.tar.gz.sha256
tar -xzf loha-port-forwarder.tar.gz
cd loha-port-forwarder
sudo ./install.sh
```

如果你的环境已经安装 GitHub CLI，并且希望在校验和之外再做 provenance 校验，还可以执行：

```bash
gh attestation verify loha-port-forwarder.tar.gz --repo wangfeng28/loha-port-forwarder
```

安装器的主线顺序是：

1. 预检与已有配置导入。
2. 网络环境。
3. 对外暴露与保护。
4. 默认出口 NAT。
5. 高级设置。
6. 摘要确认。

第一次安装时，建议按这个思路理解：

1. 先确认语言。
2. 如果 `./loha.conf` 或 `/etc/loha/loha.conf` 已存在，安装器会从其中选择一份作为起始配置。
3. 再确认主外部接口、对外暴露用外部 IPv4 地址、主外部 IP、内部接口和内部网络。
4. 然后决定保护范围、Hairpin NAT 和默认出口 NAT。
5. 最后再看高级设置，例如授权模式、WAN-to-WAN、TCP MSS Clamp、严格内部源地址校验、`RP_FILTER_MODE` 和 `CONNTRACK_MODE`。

安装完成后，建议立刻做最基本的验证：

```bash
sudo loha config show
sudo loha doctor
sudo loha list
sudo nft list table ip loha_port_forwarder
```

如果你想用机器可读方式检查安装后的状态，现在可以直接看 `sudo loha config show --json` 里的 `control_plane` 摘要；其中会包含 desired/applied revision、pending actions，以及上一次 apply 的结果。需要排查控制面同步状态时，优先看这里和 `loha doctor`，不要手工修改 `/run/loha/` 下的文件。

### 非交互安装与演练

本节里的命令默认你已经位于一个解压后的 release 目录或本地工作树中。

如果你已经准备好了配置文件，可以使用非交互路径：

```bash
sudo ./install.sh --non-interactive
```

如果你想先看计划，不改系统：

```bash
sudo ./install.sh --non-interactive --dry-run
```

非交互安装时，起始配置的选择顺序是：

1. `./loha.conf`
2. `/etc/loha/loha.conf`
3. 当前环境探测结果

安装器只会选一份起始配置，不会把两份配置做字段级合并。

一个稳妥的非交互流程通常是：

1. 先把你确定的值写进 `./loha.conf`。
2. 执行一次 `--dry-run`。
3. 确认计划无误后再执行真正安装。
4. 安装完成后再执行 `loha doctor` 和 `nft list table ip loha_port_forwarder`。

### 配置文件与安装结果

这一节只需要记住三件事。

第一，`/etc/loha/loha.conf` 是 LOHA 自己维护的配置文件，它不是给 shell 执行的脚本。更容易理解的方式是，把它看成“一份由 LOHA 负责读写的参数清单”。

它在磁盘上的保存格式很统一：

```ini
KEY="VALUE"
```

实际只要记住：

- 每个配置键都按同一种格式保存。
- 安装器和 `loha config` 会按稳定顺序重写整份文件。
- 像 `export KEY="VALUE"`、`KEY = "VALUE"` 这类旧式 shell 写法，不是当前主线支持面。

第二，安装器和 `loha config` 在输入阶段仍然接受少量“省事写法”，例如：

- `EXTERNAL_IFS=auto`
- `LISTEN_IPS=auto`
- 推荐值接受流程里的部分 toggle 型 `auto`

但这些写法不会原样落盘到 `/etc/loha/loha.conf`。写回之前，LOHA 会先把它们变成明确的最终值。换句话说，落盘结果保存的是“最后确认后的答案”，而不是“你当时为了方便怎么输入的”。

第三，安装成功后，`/etc/loha/loha.conf` 会按 LOHA 的统一格式整体重写。因此旧文件里的注释、自定义键、原有排版和历史 shell 风格写法，都不应被当成会继续保留的内容。

默认安装布局包括：

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
- `/etc/sysctl.d/90-loha-conntrack.conf` (按需)
- `/etc/modprobe.d/loha-conntrack.conf` (按需)
- `/run/loha/`

其中 `/etc/loha/state.json`、`/etc/loha/txn/` 和 `/run/loha/` 下的额外文件，属于 LOHA 自己维护的控制面元数据。它们用于保存 desired state revision、staged transaction、runtime sync 状态，以及恢复时需要的 breadcrumbs；它们不是第二套给用户手工维护的配置入口。

### 控制面一致性与并发修改

LOHA 的设计目标之一，就是让常见控制面写操作不要依赖“刚好没撞车”的 shell 时序。

实际可以这样理解：

- `loha.conf` 和 `rules.conf` 会被当作一组 desired state 一起看待，而不是两份互不相关的文件
- `config set`、别名和端口规则改动、raw `rules.conf` 编辑、rollback、install、uninstall，以及 apply/reload 这些会改控制面状态的路径，都走同一套 control-plane transaction
- LOHA 会用内部独占锁把这些写操作串行化；如果已经有别的控制面改动在进行，后来的调用会先短暂等待，之后明确报锁冲突，而不是把多次写入悄悄交错到一起
- raw `rules.conf` 编辑会先在 staged 副本上校验，通过后才提交，所以一次失败编辑不会直接污染 live 文件对

对运维和自动化来说，最值得记住的是：

- `/etc/loha/state.json`、`/etc/loha/txn/` 和 `/run/loha/` 都应视为 LOHA 自己维护的元数据，不要手工编辑
- 需要区分 desired state、applied state、pending action 或最近一次 apply 错误时，优先看 `loha config show --json` 和 `loha doctor`
- 如果自动化收到锁冲突结果，应把它当成真实的控制面竞争信号，按显式重试策略处理，而不是假定这次写入已经部分生效

### 卸载与升级

如果你是通过 release bootstrap 路径安装，而且没有保留本地 release 目录，那么在执行 `./uninstall.sh` 之前，需要先重新下载并解压对应 release 压缩包。

卸载：

```bash
sudo ./uninstall.sh
```

安全的非交互卸载。会删除已安装的 LOHA 程序文件，但默认保留 `loha.conf`、`rules.conf`、`history/` 以及系统调优文件：

```bash
sudo ./uninstall.sh -y
```

彻底删除所有由 LOHA 管理的文件，包括配置、历史快照和内核调优文件：

```bash
sudo ./uninstall.sh --purge
```

非交互执行彻底删除：

```bash
sudo ./uninstall.sh -y --purge
```

推荐升级路径：

1. 先备份 `/etc/loha/`。
2. 下载并解压最新 release 压缩包，或更新你的本地工作树。
3. 重新执行安装器。
4. 用 `loha list` 和 `nft list table ip loha_port_forwarder` 做一次确认。

正常升级不需要先卸载，直接重新运行安装器才是预期路径。

## 7 日常使用

### 先掌握这条最小工作流

如果你只是想新增一个最小可工作的转发，最稳妥的顺序是：

1. 先给后端主机起一个别名。
2. 再添加端口规则。
3. 执行 `reload`。
4. 用 `list`、`config show` 和 `doctor` 验证结果。

对应示例：

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

如果你是整段端口映射，也可以这样写：

```bash
sudo loha port add tcp 5001-5100 VM_WEB
```

如果你希望“对外暴露范围”和“后端目标范围”起始端口不同，但长度一致，也可以这样写：

```bash
sudo loha port add tcp 8080+9 VM_WEB 18080+9
```

这表示对外暴露 `8080-8089`，并转发到 `18080-18089`。这两个范围只要求长度一致，不要求起始端口相同。

### 什么时候用交互菜单

第一次上手或偶尔维护时，推荐先用：

```bash
sudo loha
```

主菜单围绕几类任务组织：

- 查看当前状态和规则。
- 管理别名。
- 添加和删除端口转发。
- 应用规则。
- 查看渲染后的 `nft` 规则。
- 进入高级设置。
- 切换语言。

这条路径适合：

- 第一次熟悉 LOHA 的人。
- 低频人工维护。
- 想边看当前状态边改配置的人。

有两点值得先知道：

- “编辑 `rules.conf`”属于高级操作，进入前会有明确确认。
- 高级设置里的很多项都可以独立调整，不必每次都重跑完整向导。

### 什么时候用 CLI

CLI 更适合这些工作：

- 脚本化维护。
- 批量增删规则。
- 与 Ansible 或 Agent 对接。
- 在不进入交互菜单的前提下做精确变更。

日常最常用的几个入口是：

- `loha list` 查看当前保存的配置和映射摘要。
- `loha config show` 查看核心配置、运行时绑定和系统集成状态。
- `loha doctor` 做更完整的诊断。
- `loha config wizard` 交互式修改核心配置。
- `loha config rollback` 回退历史快照。

这里要区分两个命令的定位：

- `loha list` 是管理面摘要，不是完整 live 诊断。
- `loha doctor` 才会把 `systemd`、live `nft`、运行时绑定和系统特性一起纳入检查。

### 修改核心配置时记住这几点

如果你改动的不是端口映射，而是核心网络行为，建议记住下面这组规则：

- 用 `loha config wizard` 修改核心配置最稳。
- `loha config set` 适合你已经明确知道要改哪个键。
- `AUTH_MODE` 改动后，应显式执行 `loha reload --full`。
- `loha config wizard` 里的高级网关设置只会写入 `loha.conf`，不会立即应用 `rp_filter` 或 `conntrack`。
- 如果你要立刻应用 `rp_filter` 或 `conntrack`，应使用对应专用命令或高级菜单入口。

如果你偏向自动化路径，可以多利用：

- `--json`
- `--check`
- `--dry-run`

它们能让“先验证、后落盘、再应用”的流程更清楚。

## 8 规则文件

LOHA 的规则文件是：

```text
/etc/loha/rules.conf
```

它只保存两类记录：

- `ALIAS`
- `PORT`

一个典型例子：

```text
# ALIAS  <name>  <ip>
ALIAS   VM_WEB  192.168.10.20
ALIAS   VM_DB   192.168.10.21

# PORT   <proto> <orig_port_spec> <dest_addr> <dest_port_spec>
PORT    tcp     8080        VM_WEB      80
PORT    tcp     3306        VM_DB       3306
PORT    tcp     5001-5100   VM_WEB      5001-5100
```

直接编辑 `rules.conf` 在这些情况下很有用：

- 你要一次性改很多条规则。
- 你已经习惯文本编辑器工作流。
- 你想把大量改动作为一次整体审查。

手工编辑时要注意：

- `rules.conf` 只接受规范端口格式，也就是单端口或 `start-end` 范围。
- `5001+99` 这种 `+offset` 简写只支持在 CLI 和 TUI 输入时使用，写入文件前会被规范化。
- 交互菜单里的编辑入口只接受单个可执行文件名或路径形式的 `EDITOR`。

一个稳妥的手工编辑流程是：

1. 先备份文件。
2. 以 root 身份编辑 `/etc/loha/rules.conf`。
3. 保存后执行 `sudo loha reload`。
4. 再用 `sudo loha list` 和 `sudo nft list table ip loha_port_forwarder` 检查结果。

如果你不想手工编辑文件，但又要一次删掉多条规则，可以用 `port prune`。例如：

```bash
sudo loha port prune --dest VM_WEB
sudo loha port prune --proto tcp --range 5001-5100
```

它的关键语义是：

- 至少要提供一个过滤条件。
- `--range` 匹配的是原始监听端口范围。

注意：

- 只有整条规则的原始监听范围完整落在过滤区间内时，这条规则才会被删除。
- 如果范围规则只是部分重叠，LOHA 不会自动拆分，而是保持该规则原样不动。

例如，假设当前有两条规则：

```text
PORT    tcp     5001-5100   VM_WEB      5001-5100
PORT    tcp     5090-5120   VM_WEB      5090-5120
```

如果执行：

```bash
sudo loha port prune --proto tcp --range 5001-5100
```

结果会是：

- 第一条会被删除，因为它的原始监听范围 `5001-5100` 整段都落在过滤区间内。
- 第二条不会被删除，因为它虽然和过滤区间有重叠，但尾部的 `5101-5120` 已经超出了过滤区间。

LOHA 不会把第二条自动拆成两条，例如“删掉 `5090-5100`，保留 `5101-5120`”。它的行为是：要么删整条，要么保持原样不动。

补充说明：

- 部分重叠的监听端口范围会被直接拒绝，不会作为相互竞争的 `dnat_rules` map key 继续交给 nftables。
- 作为额外防线，即使有人绕过正常 parser 手工构造了无效内部规则对象，renderer 也会在提交给 nft 之前拒绝冲突的重复 `dnat_rules` key。

例如，假设当前有两条规则：

```text
PORT    tcp     5001-5100   VM_WEB      5001-5100
PORT    tcp     5090-5120   VM_API      5090-5120
```

第二条在 `5090-5100` 这段和第一条发生了重叠，但又把这些端口指向了不同后端。LOHA 会在正常规则校验阶段直接拒绝这种重叠；即使有人绕过 parser 手工构造出这种内部对象，renderer 也会把它视为非法的冲突 `dnat_rules` key，而不会继续提交给 nft。

## 9 高级功能

### 高级 NAT

当你需要 Hairpin NAT 或 WAN-to-WAN 这类场景时，就需要理解 `rp_filter`。

`rp_filter` 是 Linux 的反向路径过滤机制。默认更严格的策略对普通网关是合理的，但在某些高级 NAT 场景下，它会显得过于保守。

LOHA 提供四种管理模式：

- `system`
- `strict`
- `loose-scoped`
- `loose-global`

通常可以这样理解：

- 不想让 LOHA 接管 `rp_filter`，就用 `system`。
- 只想在当前管理接口上保持严格检查，用 `strict`。
- 需要 Hairpin NAT 或 WAN-to-WAN，但又不想全局放宽，优先考虑 `loose-scoped`。
- 确实需要更宽松的全局行为时，再考虑 `loose-global`。

专用命令或高级菜单入口会立即改写 LOHA 管理的 sysctl 文件并执行 `sysctl --system`。而 `loha config wizard` 里的高级网关设置只会写入配置，不会立即应用。

### 授权模式怎么选

对大多数用户来说，选择规则很简单：

- 不确定现网里有没有复杂 `ct mark` 规划，先用默认 `ct mark` 模式。
- 现网已经大量依赖 `ct mark`，希望把 LOHA 的授权语义隔离出去，再考虑 `ct label` 模式。

当前实现里：

- 无论是 `ct mark` 还是 `ct label`，静态冲突检查都会先分析系统中现有的 `nft` 规则，确认 LOHA 准备使用的值是否已经被别的规则占用。
- `ct mark` 模式会在静态检查基础上继续做更完整的动态冲突检测；当运行环境允许时，它还会进一步检查运行时的 conntrack mark 使用情况。
- `ct label` 模式更适合隔离已有 mark 规划。它同样会先看现有 `nft` 规则里的 `ct label` 用法，尤其是 LOHA 自身 `loha_port_forwarder` table 之外的部分；当前这条路径主要依赖静态冲突检测。

无论选哪条路径，都要记住一件事：切换授权模式不是普通 map 热更新。它会影响控制面结构，因此更接近一次完整重建。

### conntrack 调优

如果宿主机要承载大量 NAT 连接，`conntrack` 很容易成为真正的容量边界。

当你遇到这些现象时，应优先检查它：

- 高峰期新连接建立失败。
- 内核日志出现 `nf_conntrack: table full`。
- 宿主机需要承载大量短连接或高并发转发。

LOHA 内置了几类能力：

- 查看当前 `conntrack` 状态。
- 使用保守、标准、高并发档位。
- 使用自动估算或自定义模式。
- 在切回 `system` 时清理自己管理的调优文件。

和 `rp_filter` 一样，专用 `conntrack` 命令会立即尝试应用，而 `loha config wizard` 的高级网关设置只会写入期望值。

### 配置历史与回退

如果 `ENABLE_CONFIG_HISTORY=on`，LOHA 会在修改 `loha.conf` 或 `rules.conf` 前维护历史快照。默认情况下：

- 快照目录是 `/etc/loha/history/`。
- 常规 history 最多保留最近 5 份。
- 10 分钟窗口内的高频小改动会优先复用最新槽位。
- 最近一次成功 rollback 还会保留单独的 rollback checkpoint，它不计入那 5 份常规上限。

这使得两类工作变得更安全：

- 高频微调规则。
- 回退最近一次错误修改。

如果你希望恢复后立刻应用，可以使用 `loha config rollback ... --apply`。

### 其它高级网关设置

除了上面几项，LOHA 还提供一些更偏网关侧的独立开关，包括：

- WAN-to-WAN 转发。
- TCP MSS Clamp。
- `nftables` 规则计数器级别。
- 严格内部源地址校验。
- 语言切换与版本查看。

这些能力大多都能在高级菜单里独立调整，不必每次都回到安装器或共享向导。

## 10 与现有防火墙共存

LOHA 不是用来接管宿主机全部防火墙职责的；它负责的是把端口转发收口成更清楚的控制层。

对大多数使用 LOHA 的宿主机来说，如果主机直面公网，系统防火墙仍然应该启用并认真配置。用了 LOHA，不等于可以不再管理宿主机防火墙。

这意味着它经常会与这些组件共存：

- Proxmox Firewall
- UFW
- Firewalld
- `nftables.service`
- `netfilter-persistent`
- 传统 `iptables` 或 `ip6tables` 服务

日常运维里要先记住两点：

- LOHA 负责的是自己的暴露路径和相应前置控制，不代表云安全组、运营商过滤或后端主机防火墙会自动同步放行。
- 外部访问不通时，不能只看 LOHA，也要同时看宿主机其它防火墙层和后端主机自身状态。

安装器会尽量让 `loha.service` 与现有防火墙 owner 保持轻耦合：

- 基础启动顺序依赖 `network.target`。
- 如果能识别当前真正负责写宿主机规则的服务，只额外添加一条 `After=`。
- 不会自动给对方加 `Requires=` 或 `PartOf=`。

探测优先级大致是：

1. 在 Proxmox VE 上跟随当前宿主机防火墙后端。
2. 在其他 Linux 主机上，按常见防火墙服务的 active 或 enabled 状态识别。
3. 如果识别不到已知 owner，就只回退到 `network.target`。

这条设计的目标不是把 LOHA 变成另一个防火墙管理器，而是尽量避免自己的规则加载顺序被上游防火墙覆盖掉。

## 11 排错建议

### 安装前先演练

如果你准备第一次安装或重装，优先做一次：

```bash
sudo ./install.sh --dry-run
```

它不会修改系统，但能先暴露很多环境级问题。

### 先看摘要 诊断 规则表

多数问题先看这三处就能缩小范围：

```bash
sudo loha list
sudo loha doctor
sudo nft list table ip loha_port_forwarder
```

它们分别回答三件事：

- LOHA 自己保存了什么。
- LOHA 认为系统哪里异常。
- 内核里现在到底有没有 `loha_port_forwarder` 表。

### 外部访问不通时这样查

推荐顺序：

1. `sudo loha doctor`
2. `sudo loha list`
3. `sudo nft list table ip loha_port_forwarder`
4. 检查云安全组或上游过滤
5. 检查后端主机默认网关
6. 检查后端主机监听状态和本机防火墙

如果问题只出现在 Hairpin NAT 或 WAN-to-WAN 场景，再补查当前 `rp_filter` 状态：

```bash
sudo loha rpfilter status
sudo sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter
```

### reload 失败时这样分层

`reload` 失败常见原因包括：

- `rules.conf` 语法错误。
- 别名引用错误。
- 授权参数冲突。
- 外部绑定不合法，例如 `LISTEN_IPS` 不属于 `PRIMARY_EXTERNAL_IF`。
- `systemd` 或 `nft` 运行状态异常。

建议从这两步开始：

```bash
sudo loha doctor
sudo /usr/local/libexec/loha/loader.sh check
```

如果 `loader.sh check` 已经失败，优先修配置和规则语法；如果它通过了，但服务仍然异常，再看：

```bash
sudo systemctl status loha --no-pager
sudo journalctl -u loha -b --no-pager
```

如果你刚改过 `AUTH_MODE` 或其它结构性配置，排障时可以直接改走完整路径：

```bash
sudo loha reload --full
```

### 高并发或 table full

如果你怀疑问题出在容量而不是语法，先看：

```bash
sudo loha conntrack status
```

当出现 `table full` 时，优先考虑：

- 提高 `nf_conntrack_max`
- 调整 buckets 或 hashsize
- 重新评估宿主机内存和连接模型

## 12 常见问题

### FAQ 1 先授权再清位会不会浪费性能

会增加一点额外成本，但通常不是主要矛盾。

`ct mark` 和 `ct label` 本质上都是内核连接跟踪里的元数据操作，单次读写成本通常不高。真正有意义的对比，不是“多一次元数据操作”和“什么都不做”之间的差距，而是：

- 用很轻的一次授权状态读写，换取更清楚的授权边界和更稳定的规则结构；
- 或者把同样的复杂度转移成更长的规则链、更多条件分支和更混乱的维护成本。

如果不用这套模型，很多判断就只能转移到更长的匹配链、更分散的放行条件，或者更靠后的宿主机防火墙路径里。规则少时差异不明显，规则多起来后，审查和维护成本会明显放大。

对 LOHA 这种会长期维护一批端口映射的工具来说，这种交换通常是划算的：用一点很轻的授权状态开销，换来更清楚的命中语义、更稳定的 map 查表路径，以及更容易长期维护的控制面。

### FAQ 2 Pangolin 和 LOHA 怎么分工

如果你现在把 Pangolin 直接跑在 PVE 宿主机上，同时还让它承担大量基础转发，通常更清楚的分工是：

1. 在宿主机上安装 LOHA。
2. 把 Pangolin 放到单独 VM。
3. 用 LOHA 把 `80/tcp`、`443/tcp`、`51820/udp` 和 `21820/udp` 转给 Pangolin VM。
4. 让 Pangolin 继续负责它擅长的 Web 反代、认证、策略和穿透。

这样做的原因很直接：

- LOHA 更适合宿主机上的 L3 和 L4 转发控制。
- Pangolin 更适合应用层入口。
- 宿主机职责和应用入口职责分开之后，边界更清楚，也更容易维护。

这样做的收益也不只是性能。更重要的是职责拆分会更干净：宿主机负责公网入口、基础 NAT 和端口转发，Pangolin VM 负责站点、证书、身份认证、访问策略和穿透能力。

如果某些服务根本不需要 Pangolin 的应用层能力，那么对应的 TCP 或 UDP 端口也可以直接由 LOHA 转发给目标后端，而不必全部先绕到宿主机上的用户态代理。

### FAQ 3 上游防火墙后端变化后怎么办

例如在 Proxmox VE 上，节点开启 `nftables: 1` 后，宿主机防火墙后端可能从 `pve-firewall.service` 变成 `proxmox-firewall.service`。

此时有三种常见处理方式：

1. 手工修改 `/etc/systemd/system/loha.service`，再执行 `systemctl daemon-reload`。
2. 重新运行 `sudo ./install.sh --non-interactive`。
3. 重新运行 `sudo ./install.sh`，并接受已保存的默认值。

后两种方式会让安装器重新计算当前环境下正确的 `After=` 目标。

### FAQ 4 无法写入 rules.conf 通常是什么原因

大多数情况下是权限问题，不是规则语法问题。

像新增别名、修改端口规则、`reload`、`doctor` 这类命令，通常都应通过具备 `sudo` 权限的管理员账号执行，例如：

```bash
sudo loha alias add VM_WEB 192.168.10.20
sudo loha port add tcp 8080 VM_WEB 80
sudo loha reload
```

`loha version` 这类纯读取版本信息的命令例外，但它不代表大多数管理命令也不需要 root。

### FAQ 5 当前版本是否必须依赖 systemd

按当前实现和本手册覆盖范围来说，是的。

LOHA 的数据面仍然是内核里的 `nftables` 规则，不是常驻用户态转发进程；但安装器、service 管理、`reload` 联动和 `doctor` 输出当前都围绕 `systemd` 工作流设计。

## 13 命令参考

大多数命令需要 root 权限；`loha version` 是最常见的例外。

### 如何阅读命令写法

- `<...>` 表示必填参数。
- `[...]` 表示可选参数。
- 命令名、flag、配置键、路径和其它 literal token 保持实际写法，不翻译。
- 如果某个参数名不够直观，会在命令下面补一行本地语言说明。

### 常用命令总览

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

### 别名与端口规则

```bash
sudo loha alias add <name> <ip>
sudo loha alias rm <name>

sudo loha port add [--force] <tcp|udp> <orig_port_spec> <dest_addr> [dest_port_spec]
sudo loha port rm <tcp|udp> <orig_port_spec>
sudo loha port prune [--dest <alias|ip>] [--proto <tcp|udp>] [--range <orig_port_spec>]
```

补充说明：

- 别名必须以 `HOST_` 或 `VM_` 开头。
- `dest_addr` 可以是别名，也可以是 IPv4 地址。
- `orig_port_spec` 和 `dest_port_spec` 可以是单端口或等长范围。
- `5001+99` 这类写法只在 CLI 和 TUI 输入阶段可用。
- `port add --force` 用于跳过本机监听冲突检查。

参数说明：

- `orig_port_spec`：外部监听端口，可以是单端口，也可以是端口范围。
- `dest_addr`：目标后端，可以写别名，也可以直接写 IPv4 地址。
- `dest_port_spec`：后端目标端口；不写时默认复用外部端口。

示例：

```bash
sudo loha port add tcp 8080 VM_WEB 80
sudo loha port add tcp 8001+50 VM_WEB 9001+50
sudo loha port prune --dest VM_WEB --proto tcp --range 5001-5100
```

### 渲染、重载与诊断

```bash
sudo loha rules render
sudo loha list
sudo loha reload
sudo loha reload --full
sudo loha doctor
loha version
```

补充说明：

- `loha rules render` 会输出当前完整渲染后的 `nft` ruleset，但不会真正应用。
- 它是根据当前 `loha.conf` 和 `rules.conf` 做渲染预览，不会去读取内核里的 live `nft` table。
- 如果你想看当前已经生效的内核状态，请用 `sudo nft list table ip loha_port_forwarder`。
- `loha list` 展示的是保存配置和映射摘要，不是完整 live 诊断。
- `loha doctor` 会把 `systemd`、live `nft`、listener conflict、runtime binding 和系统特性一起检查。

### 配置与回退

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

补充说明：

- `config show` 会把核心配置、运行时绑定和系统特性状态一起显示出来。
- `config set AUTH_MODE ...` 只会写配置，不会自动完整重建控制面；之后应执行 `loha reload --full`。
- `config normalize` 会把当前 canonical 配置重写为稳定格式，并物化输入 shortcut。
- `config wizard` 更适合交互式修改核心配置。

参数说明：

- `config rollback [latest|<1-5>] [--apply]` 里的 `latest` 表示回退到当前最近的可用目标。
- `<1-5>` 表示按序号选择快照。
- `--apply` 表示回退文件后立刻执行运行时应用；不带时只恢复文件。

### rp_filter 与 conntrack

```bash
sudo loha rpfilter status
sudo loha rpfilter set <system|strict|loose-scoped|loose-global>

sudo loha conntrack status
sudo loha conntrack profile <conservative|standard|high>
sudo loha conntrack auto <peak> [memory_percent]
sudo loha conntrack set <max> [memory_percent]
sudo loha conntrack system
```

补充说明：

- 这些命令支持独立维护系统集成状态，不必每次都回到完整配置向导。
- `rpfilter` 和 `conntrack` 的专用命令会立即走对应 apply 路径。
- `conntrack system` 用于把 `conntrack` 管理权交回系统。

参数说明：

- `rpfilter set <system|strict|loose-scoped|loose-global>`：选择 LOHA 怎样管理 `rp_filter`。
- `conntrack profile <conservative|standard|high>`：直接套用预设档位。
- `conntrack auto <peak> [memory_percent]`：`<peak>` 是估算的峰值并发连接数，`[memory_percent]` 是允许 `conntrack` 使用的内存百分比。
- `conntrack set <max> [memory_percent]`：`<max>` 是你想直接设定的最大并发连接数，`[memory_percent]` 是对应内存百分比。

示例：

```bash
sudo loha conntrack auto 300000 40
sudo loha conntrack set 500000 50
```

### 面向自动化的能力

以下能力特别适合脚本、编排工具和 Agent：

- `--json`：适用于 `list`、`rules render`、`doctor`、`config show`、`config set`、`reload`、`config history status/show`、`config rollback`、别名与端口规则写操作、`rpfilter`、`conntrack` 等命令。
- `--check` 或 `--dry-run`：适用于会修改 `loha.conf`、`rules.conf` 或系统调优文件的命令。
- 稳定的结果分类、错误分类和退出码，便于调用方按机器语义判断结果。
- 当另一条控制面写路径已经持有独占写锁时，会明确返回锁冲突，而不是默默把并发写入交错在一起。

`--check` 会校验请求并预演目标结果，但不会真正写文件、创建历史快照或执行 `sysctl --system`。

如果你是从自动化侧消费 LOHA 的控制面状态，当前最实用的是下面这些字段和入口：

- `config show --json`：包含 `control_plane.desired_revision`、`applied_revision`、`runtime_synced`、`pending_actions` 和 `last_error`
- `reload --json`：返回 requested/effective mode，以及当前 revision 与 pending action
- `config history status/show --json`：直接提供 snapshot 状态，不需要解析人类输出
- `config rollback --json`：直接说明恢复来源，以及是否还存在例如 `reload` 这类待同步动作

## 14 文档 测试 翻译

如果你想继续深入，推荐按下面的入口查：

- 快速定位和项目介绍： [README_zh_CN.md](./README_zh_CN.md)
- 英文版本手册： [MANUAL.md](./MANUAL.md)
- 术语与翻译基线： [docs/translation-baseline.md](./docs/translation-baseline.md)
- 配置模型和 canonical 契约： [docs/canonical-config-model.md](./docs/canonical-config-model.md) 与 [docs/config-file-contract.md](./docs/config-file-contract.md)
- 安装器与交互行为： [docs/installer-flow.md](./docs/installer-flow.md)、 [docs/interaction-contract.md](./docs/interaction-contract.md)、 [docs/summary-confirmation-design.md](./docs/summary-confirmation-design.md)
- 运行边界与渲染行为： [docs/multi-external-boundary.md](./docs/multi-external-boundary.md) 与 [docs/nft-renderer-architecture.md](./docs/nft-renderer-architecture.md)
- 验证基线： [docs/validation-matrix.md](./docs/validation-matrix.md)

当前仓库的验证入口主要是：

- `scripts/run_tests.sh`
- `scripts/run_smoke.sh`

翻译相关文件位于：

- 仓库内： `locales/*.toml`
- 安装后： `/usr/local/share/loha/locales/*.toml`

LOHA 已为多语言做好准备。无论你是想修正文案、补充新语言，还是改进 README 和 MANUAL，本项目都欢迎这类贡献。
