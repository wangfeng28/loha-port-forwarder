# LOHA Canonical Configuration Model

## Purpose

This document freezes the semantic baseline of the persisted configuration model in the current Python implementation of LOHA. It defines:

- which fields are the only source of truth
- which fields are input-layer shortcuts rather than persisted results
- which fields are shared dependencies for the installer, the shared wizard, the renderer, and the loader

Related documents:

- [config-file-contract.md](./config-file-contract.md)
- [installer-flow.md](./installer-flow.md)
- [interaction-contract.md](./interaction-contract.md)
- [summary-confirmation-design.md](./summary-confirmation-design.md)

## Frozen Decisions

### 1. `loha.conf` stores only the canonical source of truth

Persisted truth now comes only from the canonical key set itself:

- external entry and exposure
- internal networks and protection scope
- default egress NAT
- advanced behavior and system integration

### 2. Input shortcuts are not part of the long-term persisted result

The following inputs may still exist as shortcuts at input time, but they must be materialized into explicit values before save:

- `EXTERNAL_IFS=auto`
- `LISTEN_IPS=auto`
- toggle-style `auto` values used only for accepting recommended defaults

In other words:

- the input layer may accept `auto`
- `loha.conf` does not persist these shortcuts
- the renderer and loader no longer depend on these shortcuts to keep guessing the real values

### 3. Collection fields do not carry ordering semantics by default

The following fields are all set-like collections, not ordered lists where the first item implies a primary value:

- `EXTERNAL_IFS`
- `LISTEN_IPS`
- `LAN_IFS`
- `LAN_NETS`
- `PROTECTED_NETS`
- `EGRESS_NETS`
- `INTERNAL_IFS`
- `TRUSTED_INTERNAL_NETS`

If the system needs a primary value, it must be represented by a separate explicit field.

### 4. The current product boundary is still a single external interface

The persisted model still keeps:

- `EXTERNAL_IFS`
- `PRIMARY_EXTERNAL_IF`

But the formally supported boundary is still:

- one primary external interface
- one or more external IPv4 addresses used for exposure on that interface

Full multi-external support is not part of the current product promise.

## Core Fields

### A. Network Topology and Exposure

| Field | Required | Type | Meaning | Constraint |
| --- | --- | --- | --- | --- |
| `EXTERNAL_IFS` | Yes | Interface set | The set of interfaces that LOHA treats as the external entry side | The current mainline supports only one value |
| `PRIMARY_EXTERNAL_IF` | Yes | Single interface | The primary external interface | Must belong to `EXTERNAL_IFS` |
| `LISTEN_IPS` | Yes | IPv4 set | The external IPv4 addresses used for exposure | Must be non-empty |
| `DEFAULT_SNAT_IP` | Yes | Single IPv4 | The default egress SNAT source IP, and also the primary external IP | Must belong to `LISTEN_IPS` |
| `LAN_IFS` | Yes | Interface set | The internal interface set | Must be non-empty |
| `LAN_NETS` | Yes | IPv4 CIDR set | The internal network set | Must be non-empty |

Notes:

- `LISTEN_IPS` expresses which external IPv4 addresses are used for exposure
- `DEFAULT_SNAT_IP` expresses which address is used for default egress SNAT
- they are related, but they are not synonymous fields

### B. Protection and Default Egress NAT

| Field | Required | Type | Meaning | Constraint |
| --- | --- | --- | --- | --- |
| `PROTECTION_MODE` | Yes | Enum | Protection scope | `backends` / `nets` / `both` |
| `PROTECTED_NETS` | Conditionally required | IPv4 CIDR set | Explicit protected networks | Must be explicitly saved when `PROTECTION_MODE=nets|both` |
| `ENABLE_HAIRPIN` | Yes | Boolean | Whether Hairpin NAT is enabled | `on` / `off` |
| `ENABLE_EGRESS_SNAT` | Yes | Boolean | Whether LOHA manages default egress SNAT | `on` / `off` |
| `EGRESS_NETS` | Conditionally required | IPv4 CIDR set | Networks covered by default egress NAT | Must be explicitly saved when `ENABLE_EGRESS_SNAT=on` |

### C. Authorization and Additional Forwarding Behavior

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `AUTH_MODE` | Yes | Enum | Authorization mode: `mark` or `label` |
| `DNAT_MARK` | Conditionally required | Single value | The `ct mark` value when `AUTH_MODE=mark` |
| `DNAT_LABEL` | Conditionally required | Single value | The `ct label` value when `AUTH_MODE=label` |
| `ENABLE_WAN_TO_WAN` | Yes | Boolean | WAN-to-WAN forwarding support |
| `ENABLE_TCPMSS_CLAMP` | Yes | Boolean | TCP MSS clamp on WAN egress |
| `COUNTER_MODE` | Yes | Enum | nft counter retention level |

### D. Strict Internal Source Validation and System Integration

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `ENABLE_STRICT_LAN_VALIDATION` | Yes | Boolean | Whether strict internal source address validation is enabled |
| `INTERNAL_IFS` | Conditionally required | Interface set | Interfaces covered by strict validation |
| `TRUSTED_INTERNAL_NETS` | Conditionally required | CIDR set | Trusted source networks for strict validation |
| `ENABLE_CONFIG_HISTORY` | Yes | Boolean | Whether config snapshots are enabled |
| `RP_FILTER_MODE` | Yes | Enum | `rp_filter` management mode |
| `CONNTRACK_MODE` | Yes | Enum | `conntrack` management mode |
| `CONNTRACK_TARGET_MAX` | Conditionally required | Integer | Target value in `custom` mode |
| `CONNTRACK_PEAK` | Conditionally required | Integer | Peak input for `auto` mode |
| `CONNTRACK_MEMORY_PERCENT` | Conditionally required | Integer | Memory percentage input for `auto` / `custom` |
| `LOCALE` | Yes | Single value | The current locale |

## Materialization Rules Before Save

Before a config is saved, all of the following must be true:

- `PRIMARY_EXTERNAL_IF` must not be missing
- `DEFAULT_SNAT_IP` must not be missing
- conditional fields must be saved explicitly with either a value or an explicit empty value
- input shortcuts must be resolved into explicit canonical values first

Example:

- if `LISTEN_IPS` has only one value, the input flow may skip asking for the primary external IP separately
- but before save, that same value must still be written explicitly into `DEFAULT_SNAT_IP`

## Example

```ini
EXTERNAL_IFS="eth0"
PRIMARY_EXTERNAL_IF="eth0"
LISTEN_IPS="203.0.113.10,198.51.100.20"
DEFAULT_SNAT_IP="203.0.113.10"
LAN_IFS="vmbr1"
LAN_NETS="192.168.10.0/24,192.168.20.0/24"
PROTECTION_MODE="both"
PROTECTED_NETS="192.168.10.0/24,192.168.20.0/24"
AUTH_MODE="mark"
DNAT_MARK="0x10000000"
DNAT_LABEL=""
ENABLE_HAIRPIN="on"
ENABLE_WAN_TO_WAN="off"
ENABLE_EGRESS_SNAT="off"
EGRESS_NETS=""
ENABLE_TCPMSS_CLAMP="off"
ENABLE_STRICT_LAN_VALIDATION="off"
INTERNAL_IFS=""
TRUSTED_INTERNAL_NETS=""
COUNTER_MODE="minimal"
ENABLE_CONFIG_HISTORY="on"
RP_FILTER_MODE="system"
CONNTRACK_MODE="system"
CONNTRACK_TARGET_MAX=""
CONNTRACK_PEAK=""
CONNTRACK_MEMORY_PERCENT=""
LOCALE="zh_CN"
```

## Current Validity Conditions

This document remains valid as long as the following stay true:

- the persisted config contains only the canonical key set
- `auto` shortcuts are not written to disk
- the summary, wizard, renderer, and loader share the same field semantics
- the formal support boundary remains a single external interface
