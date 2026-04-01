# LOHA Summary and Confirmation Contract

Updated: 2026-03-25

## Purpose

This document freezes the summary and confirmation contract in the current Python implementation of LOHA. It covers:

- the installer's final confirmation page
- the pre-save confirmation page in the CLI shared wizard

The goal of the summary is not to mirror `loha.conf`. Its goal is to let users quickly confirm the meaning of the resulting setup before anything is applied.

## Fixed Structure

The summary is always divided into four sections, in this exact order:

1. network topology
2. exposure and protection
3. default egress NAT
4. advanced settings

## Display Rules by Section

### 1. Network Topology

This section always shows:

- external interface
- external IPv4 addresses used for exposure
- primary external IP
- internal interfaces
- internal networks

It also appends two kinds of runtime state:

- external interface binding
- exposure address binding

If there are any `auto`-related notes, they also appear as extra lines in this section.

### 2. Exposure and Protection

This section currently shows:

- one protection-scope line
- `Hairpin NAT`
- `PROTECTED_NETS` when `PROTECTION_MODE` is `nets` or `both`

The wording in the summary must describe the result, not just echo the raw key name `PROTECTION_MODE`.

### 3. Default Egress NAT

This section currently shows:

- when `ENABLE_EGRESS_SNAT=off`, only `Managed by LOHA: Off`
- when `ENABLE_EGRESS_SNAT=on`, it shows:
  - `Managed by LOHA: On`
  - `EGRESS_NETS`
  - the default egress source IP

### 4. Advanced Settings

The current recommended advanced values are fixed by `RECOMMENDED_ADVANCED` in [wizard.py](../src/loha/wizard.py).

Current display rules:

- if nothing deviates from the recommended values:
  - when the user never entered advanced settings, show `Advanced settings: using recommended values`
  - when the user inspected advanced settings but changed nothing in the end, show `Advanced settings: reviewed, kept recommended values`
- if some values differ from the recommendation, show only the fields that changed and whose current value is non-empty
- when `ENABLE_STRICT_LAN_VALIDATION=on`, also show `INTERNAL_IFS` and `TRUSTED_INTERNAL_NETS`

## What Must Stay Out of the Main Summary

The following must not appear in the main summary:

- `DNAT_MARK`
- `DNAT_LABEL`
- renderer-internal `define` values
- other internal state consumed only by the runtime and rendering layers

## Footer Lines

After the four fixed sections, the current implementation may append footer lines.

They currently come mainly from:

- runtime binding materialization notes
- pre-save notices

These appear before the confirmation actions, but they do not become part of the four fixed sections.

## Confirmation Action Contract

### Installer

The installer currently uses this fixed action set:

- `1. Confirm installation`
- `2. Back to network environment`
- `3. Back to exposure and protection`
- `4. Back to default egress NAT`
- `5. Back to advanced settings`
- `0. Cancel installation`

### CLI Shared Wizard

The CLI shared wizard currently uses this fixed action set:

- `1. Save configuration`
- `2. Back to network topology`
- `3. Back to exposure and protection`
- `4. Back to forwarding settings`
- `5. Back to advanced gateway settings`
- `0. Cancel`

## Example

```text
Network Topology
  External interface: eth0
  External IPv4 addresses used for exposure: 203.0.113.10,203.0.113.11
  Primary external IP: 203.0.113.10
  Internal interfaces: br0
  Internal networks: 192.168.10.0/24
  External interface binding: compatible with current runtime (explicit single-interface binding)
  Exposure address binding: compatible with current runtime (matches the configured exposure address list)

Exposure and Protection
  Protection scope: exposed backends only
  Hairpin NAT: on

Default Egress NAT
  Managed by LOHA: off

Advanced Settings
  Advanced settings: using recommended values
```
