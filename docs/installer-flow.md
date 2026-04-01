# LOHA Installer Flow

## Purpose

This document freezes the main flow, question tree, and summary-confirm structure of the LOHA installer and the shared wizard in the current Python implementation.

Related documents:

- [canonical-config-model.md](./canonical-config-model.md)
- [interaction-contract.md](./interaction-contract.md)
- [summary-confirmation-design.md](./summary-confirmation-design.md)

## Non-Goals

The current installer does not do the following:

- it does not surface system details such as `rp_filter` and `conntrack` in the mainline entry flow
- it does not try to collect a complete host-network planning document

## Core Principles

### 1. Topology first, behavior second

The installer must first establish:

- the primary external interface
- the external IPv4 addresses used for exposure
- the primary external IP
- the internal interfaces and internal networks

Only after that does it move on to:

- protection scope
- Hairpin NAT
- default egress NAT
- advanced gateway settings

### 2. Users see result semantics, not internal key names

The main interaction surface exposes only these concepts:

- external interface
- external IPv4 addresses used for exposure
- primary external IP
- internal interfaces
- internal networks
- protection scope
- default egress NAT
- advanced settings

### 3. Input shortcuts belong to the input layer

The current installer and wizard may accept:

- `EXTERNAL_IFS=auto`
- `LISTEN_IPS=auto`
- toggle-style `auto` values along the recommended-value acceptance path

But before save, those shortcuts must be materialized into explicit canonical values.

## Fixed Flows

### Installer

The installer main flow is fixed as:

1. precheck and existing-config import
2. network environment
3. exposure and protection
4. default egress NAT
5. advanced settings
6. summary and confirmation

### CLI Shared Wizard

The CLI shared wizard flow is fixed as:

1. network environment
2. exposure and protection
3. forwarding settings
4. advanced gateway settings
5. summary and confirmation

## Stage Notes

### Stage 0: Precheck and Existing-Config Import

Current behavior:

- run prechecks for root, dependencies, and resource integrity first
- if both `./loha.conf` and `/etc/loha/loha.conf` exist, choose only one of them as the starting config
- do not merge two config files field by field

### Stage 1: Network Environment

Fields collected at this stage:

- `EXTERNAL_IFS`
- `PRIMARY_EXTERNAL_IF`
- `LISTEN_IPS`
- `DEFAULT_SNAT_IP`
- `LAN_IFS`
- `LAN_NETS`

Current mainline constraints:

- only one external interface may be selected
- `LISTEN_IPS` may contain multiple external IPv4 addresses on that interface
- `DEFAULT_SNAT_IP` must be written explicitly

### Stage 2: Exposure and Protection

Fields collected at this stage:

- `PROTECTION_MODE`
- `PROTECTED_NETS`
- `ENABLE_HAIRPIN`

Current mainline wording must describe behavioral results:

- "protect exposed backends only"
- "explicit protected networks"
- "exposed backends and explicit protected networks"

### Stage 3: Default Egress NAT

Fields collected at this stage:

- `ENABLE_EGRESS_SNAT`
- `EGRESS_NETS`

Notes:

- `DEFAULT_SNAT_IP` has already been established in the network-environment stage
- this stage does not ask for the default SNAT IP again

### Stage 4: Advanced Settings

The current advanced-settings stage covers:

- `AUTH_MODE`
- `ENABLE_WAN_TO_WAN`
- `ENABLE_TCPMSS_CLAMP`
- `COUNTER_MODE`
- `ENABLE_STRICT_LAN_VALIDATION`
- `INTERNAL_IFS`
- `TRUSTED_INTERNAL_NETS`
- `RP_FILTER_MODE`
- `CONNTRACK_MODE`
- `CONNTRACK_TARGET_MAX`
- `CONNTRACK_PEAK`
- `CONNTRACK_MEMORY_PERCENT`

The current implementation allows the user to:

- accept the recommended advanced settings directly
- or enter manual advanced settings

## Interaction Constraints

- numeric menus come first
- only pure text values such as IPv4, CIDR, and CSV lists continue to use text input
- when an existing config has been imported, the flow should support moving through by pressing Enter whenever possible
- canonical materialization must be complete before save

## Saved Result

The saved `loha.conf` must satisfy all of the following:

- it contains only the canonical key set
- it contains no persisted `auto` shortcuts
- all conditional fields are written explicitly

## Change Discipline

If any of the following need to change later, update this document first and the code second:

- stage order
- which fields are collected in each stage
- the fixed section structure of the summary page
- the single-external-interface boundary
