# LOHA `nft` Renderer Architecture

Updated: 2026-03-25

## Purpose

This document describes the `nft` renderer architecture in the current Python implementation of LOHA. It answers three questions:

- how the canonical config and `rules.conf` enter the rendering layer
- which objects the current renderer actually emits
- what determines the boundary between hot reload and full reload

Related documents:

- [canonical-config-model.md](./canonical-config-model.md)
- [config-file-contract.md](./config-file-contract.md)
- [multi-external-boundary.md](./multi-external-boundary.md)
- [validation-matrix.md](./validation-matrix.md)
- [summary-confirmation-design.md](./summary-confirmation-design.md)

## Entry Points and Boundaries

The current rendering pipeline is built around [loader.py](../src/loha/loader.py) and [render.py](../src/loha/render.py):

1. the loader reads canonical `loha.conf`
2. the loader reads `rules.conf`
3. the loader validates runtime binding before rendering
4. the renderer generates the ruleset, map update, and control state
5. the loader chooses hot reload or full apply based on the control state

Current boundaries:

- runtime binding validation happens in the loader layer, not inside the renderer
- `rp_filter`, `conntrack`, and `systemd` are not part of the renderer
- the renderer is responsible only for `nft` rule text and the related control-state data

## Input Objects

The current renderer receives `RenderContext` from [models.py](../src/loha/models.py):

- `config: CanonicalConfig`
- `rules: RulesFile`

The current implementation does not have an extra intermediate "skeleton object" or a chain-level fragment registry. The renderer generates its output directly from those two objects.

## Supported Topology Boundary

The current renderer serves only the mainline product boundary:

- a single external interface
- one or more external IPv4 addresses used for exposure
- one primary external IP / default SNAT IP

Multi-external is not part of the formal support scope for the current renderer. That boundary is enforced jointly by [multi-external-boundary.md](./multi-external-boundary.md) and runtime-binding validation.

## Rendering Pipeline

The current rendering flow can be viewed as six steps:

1. read the canonical config and rules file
2. validate `EXTERNAL_IFS`, `PRIMARY_EXTERNAL_IF`, `LISTEN_IPS`, and `DEFAULT_SNAT_IP`
3. build `dnat_rules` and the protected-backend set from the port rules, while rejecting conflicting duplicate `dnat_rules` keys before anything reaches nft
4. assemble `define`, `set`, `map`, and `chain` objects from the current config
5. compute `template_checksum` and `control_state`
6. generate:
   - `full_ruleset`
   - `map_update`
   - `control_state`
   - `template_checksum`

## Output Object

The renderer returns `RenderedRuleset` from [models.py](../src/loha/models.py):

- `full_ruleset`
- `map_update`
- `control_state`
- `template_checksum`

### 1. `full_ruleset`

The full ruleset starts with an idempotent:

```nft
destroy table ip loha_port_forwarder
```

Then it rebuilds the entire `ip loha_port_forwarder` table.

### 2. `map_update`

This is the minimal update path used for hot reload. It currently includes:

- re-declaring the current `define` values
- `flush map ip loha_port_forwarder dnat_rules`
- `flush set ip loha_port_forwarder listen_ips`
- `flush set ip loha_port_forwarder protected_backend_hosts`
- re-adding elements for those objects

The renderer does not rely on nftables to resolve duplicate `dnat_rules` keys. If rendering would generate the same map key twice with conflicting targets, rendering fails before the batch leaves LOHA.

### 3. `control_state`

The control state is what decides whether the current change can use hot reload or must use full reload. It records:

- external and internal binding
- authorization mode and authorization parameters
- Hairpin NAT, WAN-to-WAN, egress, strict validation, and counters
- protection mode and protected networks
- `CORE_TEMPLATE_CHECKSUM`

If the newly rendered result does not match the control state currently on disk, `reload` is promoted to full apply.

### 4. `template_checksum`

This is currently produced from the SHA-256 of the full skeleton text and is also stored inside the control state.

## Generated Data Objects

The renderer currently generates these core objects.

### `define`

Always or conditionally generated:

- `PRIMARY_EXTERNAL_IF`
- `EXTERNAL_IFS`
- `DEFAULT_SNAT_IP`
- `LAN_IFS`
- `LAN_NETS`
- `INTERNAL_IFS`
- `TRUSTED_INTERNAL_NETS`
- `EGRESS_NETS`
- `PROTECTED_NETS`
- `DNAT_MARK` and `DNAT_MARK_CLEAR_MASK`
- or `DNAT_LABEL`

### `map`

- `dnat_rules`

### `set`

- `listen_ips`
- `protected_backend_hosts`

Notes:

- changes in object count are still represented mainly through `set` and `map`, not by cloning more rule skeletons
- port ranges are expanded into `dnat_rules` elements rather than driving a new topology variant

## Chain Responsibilities

The current `full_ruleset` always contains these chains:

- `port_forwarding`
- `prerouting`
- `output`
- `postrouting`
- `forward`

### `port_forwarding`

Responsible for:

- pre-authorization actions
- `dnat_rules` map lookup
- cleanup on misses

Current authorization differences are contained by helper functions rather than by two public template files.

### `prerouting`

Responsible for:

- jumping into `port_forwarding` only when the destination address matches `@listen_ips`

### `output`

Responsible for:

- loopback cases where the local machine accesses external IPs used for exposure

### `postrouting`

Responsible for:

- default egress SNAT
- Hairpin NAT
- return-path NAT for WAN-to-WAN

### `forward`

Responsible for:

- dropping invalid traffic
- fast path for established connections
- DHCP special cases
- anti-spoofing on WAN ingress
- optional strict internal source validation
- allowing authorized DNAT traffic
- allowing LAN-initiated egress
- enforcing protection-scope blocking

## Current Authorization Abstraction

Even though the renderer is still a single-file string assembler, authorization differences are already concentrated into a helper set:

- `_render_auth_authorize`
- `_render_auth_lookup`
- `_render_auth_miss_cleanup`
- `_forward_accept_predicate`
- `_postrouting_auth_match`
- `_protection_miss_expr`

That means the primary differences between `mark` and `label` are already narrowed to local fragments instead of two completely separate public render pipelines.

Current behavioral baseline:

- `mark` uses a dedicated authorization bit and clears that bit on misses
- `label` narrows miss semantics through `ct label` plus `ct status dnat`

## Current Hot Reload Decision Rules

Current loader behavior:

- the user requests `reload`
- if the control state matches completely, apply only `map_update`
- if the control state does not match, automatically promote to full apply

Typical cases that currently force full apply:

- `AUTH_MODE` changes
- changes to other core behavior parameters that are part of the control state

By contrast, when only the port-mapping set changes, hot reload is usually enough.

## Non-Goals

The current renderer does not handle:

- config transactions
- history or rollback
- `systemctl` operations
- `sysctl --system`
- `modprobe`
- `rp_filter` or `conntrack` file rendering

Those capabilities belong to the loader, history, or system-feature layers.

## Current Conclusion

The renderer in the current Python implementation of LOHA is not a migration draft waiting to be replaced. It is an implemented single-mainline renderer:

- input is `CanonicalConfig + RulesFile`
- output is `full_ruleset + map_update + control_state`
- topology support is fixed to the current single-external mainline
- hot reload is driven by control state and checksum

If any of the following change later:

- the control-state field set
- chain responsibilities
- the map-update boundary
- authorization-fragment semantics

update this document first, then modify [render.py](../src/loha/render.py), [loader.py](../src/loha/loader.py), and the related tests.
