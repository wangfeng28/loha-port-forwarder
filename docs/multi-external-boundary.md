# LOHA Multi-External-Interface Boundary

Updated: 2026-03-25

## Purpose

This document freezes the formal product boundary of the current Python implementation of LOHA around the multi-external-interface question.

It answers three questions:

- what the current version actually supports
- what the current version explicitly does not support
- which explicit semantics must exist before multi-external support can move forward in the future

Related documents:

- [canonical-config-model.md](./canonical-config-model.md)
- [installer-flow.md](./installer-flow.md)
- [nft-renderer-architecture.md](./nft-renderer-architecture.md)
- [validation-matrix.md](./validation-matrix.md)

## Formally Supported Scope

The current version formally supports:

1. a single external interface
2. one or more exposed external IPs on that interface
3. one explicit primary external IP / default SNAT IP
4. entry protection, default egress NAT, and WAN-to-WAN semantics built around that primary external interface

In short, the supported model is:

- `single-external + multi-listen-ip`

It is not:

- true `multi-external`

## Model-Level Extension Space That Still Exists

Even though the current product boundary is single-external, the canonical model still keeps:

- `EXTERNAL_IFS`
- `PRIMARY_EXTERNAL_IF`

That means:

- the model has not collapsed into a key set meant only for a single external interface
- if the product boundary expands later, we do not need to invent a new primary-value concept again

## How the Current Entry Layer Enforces This Boundary

### Installer and Shared Wizard

The current installer mainline and shared wizard both allow the user to choose only one external interface.

After save:

- `EXTERNAL_IFS` is materialized as a single-member set
- `PRIMARY_EXTERNAL_IF` is materialized as that interface

When `LISTEN_IPS` has multiple addresses:

- `DEFAULT_SNAT_IP` is explicitly confirmed

When `LISTEN_IPS` has only one address:

- `DEFAULT_SNAT_IP` collapses to that single address

This is explicit derivation inside the current single-external boundary. It does not imply multi-external support.

### Runtime Binding and Config Layer

`config.py` and `runtime_binding.py` currently enforce the following constraints together:

- multi-external configuration is outside the current formal support scope
- `PRIMARY_EXTERNAL_IF` cannot exist independently of `EXTERNAL_IFS`
- `DEFAULT_SNAT_IP` cannot exist independently of `LISTEN_IPS`
- `LISTEN_IPS=auto` resolves only on the primary external interface
- `EXTERNAL_IFS=auto` is accepted only when the system can resolve a unique default IPv4 egress interface

### Renderer and Loader

The current renderer and loader serve only the single-external mainline:

- the renderer rule structure is built around one primary external interface
- `reload` versus full rebuild decisions are made only for that mainline
- there is no implemented ownership mapping or symmetric-return model for multiple external interfaces

## Capabilities Explicitly Not Supported

The following capabilities must not be promised, implied, or documented as supported:

### 1. Mainline configuration for multiple external interfaces

- the installer mainline and shared wizard mainline do not support configuring multiple external interfaces with the expectation of full runtime support

### 2. `LISTEN_IPS` spread across multiple external interfaces

- the current implementation does not support distributing exposure addresses across multiple external interfaces and expecting the renderer and runtime to infer ownership correctly

### 3. Symmetric return paths

- LOHA does not promise "traffic returns through the same WAN it entered on"
- there is no complete policy-routing or return-path model today

### 4. Per-listen-IP egress ownership

- the current model does not support semantics where each `LISTEN_IP` is bound to a different external interface or a different default SNAT IP

### 5. Multi-WAN high availability or load balancing

- no WAN-level failover
- no WAN-level load balancing
- no automatic routing orchestration

## Design Shortcuts That Are Explicitly Forbidden

To avoid creating the impression that multi-external support already exists, the following shortcuts are explicitly forbidden:

### 1. Smuggling primary-value semantics through collection order

The following must not become long-term contract:

- the first item in `EXTERNAL_IFS` is the primary external interface
- the first item in `LISTEN_IPS` is the default SNAT IP

Notes:

- default derivation is still allowed in single-candidate or single-member cases
- but that must not be promoted into a long-term rule for multi-external semantics

### 2. Treating `auto` shortcuts as the fallback for multi-external behavior

The implementation must not rely on:

- persisting `EXTERNAL_IFS=auto`
- persisting `LISTEN_IPS=auto`
- continuing to guess the primary interface at runtime in multi-default-route scenarios

### 3. Exposing multi-external UI before an ownership model exists

Until there is an explicit ownership model and return-path model, multi-external selection must not appear in the main interaction flow.

## Minimum Semantics Required Before Any Future Expansion

This document does not push implementation work. It freezes the prerequisites.

If LOHA later expands beyond the single-external model, it must first define at least:

1. ownership from listen addresses to external interfaces
2. mapping from listen addresses to default SNAT IPs
3. a return-path and policy-routing model
4. visibility of ownership relationships in summary and doctor output
5. explicit rejection rules and validation coverage for unsupported cases

Until those semantics enter the model, the interaction layer, and the validation layer, no partial compatibility should be documented as "multi-external support".

## Supported-Behavior Statement for the Current Version

The stable user-facing statement for the current version should be:

- LOHA currently supports one external interface in its mainline path
- it can expose multiple external IPs on that interface
- the primary external IP / default SNAT IP is an explicit concept
- full multi-external support is outside the current formal commitment

## Current Conclusion

In the current Python repository, multi-external is not a half-finished feature. It is an explicit product boundary.

That boundary is enforced together by:

- the config model
- the interaction entry points
- runtime binding
- the renderer and loader
- the documentation and validation baseline

If that boundary is ever relaxed later, this document and the related validation docs must change first. The code should not be loosened quietly ahead of them.
