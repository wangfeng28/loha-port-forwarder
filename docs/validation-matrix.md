# LOHA Validation Matrix

Updated: 2026-03-27

## Purpose

This document freezes the validation baseline of the current Python implementation of LOHA. It answers three questions:

- which automated validation assets the repository currently relies on
- which layer of behavior each asset protects
- which risks still require additional tests or real Linux validation

Related documents:

- [canonical-config-model.md](./canonical-config-model.md)
- [config-file-contract.md](./config-file-contract.md)
- [installer-flow.md](./installer-flow.md)
- [interaction-contract.md](./interaction-contract.md)
- [multi-external-boundary.md](./multi-external-boundary.md)

## Current Validation Entry Points

The repository currently has two primary validation entry points:

1. full offline regression: `sh scripts/run_tests.sh`
2. offline smoke: `sh scripts/run_smoke.sh`

Notes:

- the current automation baseline is Python `unittest`, not shell test scripts
- if an older document still refers to `tests/*.sh`, treat that as stale information rather than a current test asset
- repository-local offline tests freeze pure logic, interaction contracts, and file-layout semantics; real `Linux + systemd + nftables` hosts still require separate validation
- real Linux validation records and templates are maintained as internal project docs and are not published in the public repository

## Validation Principles

### 1. Protect shared semantics before entry-point presentation

Validate these first:

- the canonical config model
- shared wizard and summary logic
- pure runtime-binding and system-feature logic
- renderer, loader, and transaction boundaries

Only after that do you validate:

- CLI output wording
- installer wrapper layers
- menu-entry organization

### 2. Automated regression takes priority over manual spot checks

For every change, prioritize adding:

- `unittest`
- regression coverage for shared logic
- offline smoke for key commands

Do not rely only on doing one successful manual installation.

### 2.5. Add contract tests before chasing boilerplate deduplication

For CLI, installer, and wizard entry layers:

- if repeated logic carries shared contracts such as `check/json/apply`, summary return paths, side-effect planning, or fixed action numbering, prioritize tests and convergence into shared implementation
- if repeated logic is mainly menu printing, simple input handling, or lightweight presentation boilerplate, do not keep abstracting just to look more generic

Before more structural cleanup is justified, all of the following should be true:

1. there are at least three call sites or branch copies
2. the repeated section carries shared behavioral contract
3. the abstraction will not worsen module dependency direction
4. regression coverage already freezes the old behavior

If those conditions are not met, validation effort should return to correctness, edge cases, and documented contract instead of pursuing DRY for its own sake.

### 3. Offline validation and live validation must stay layered

Offline tests can cover:

- config parsing and rewriting
- interaction flow control
- rendered ruleset skeletons
- file write ordering
- runtime locale switching

Offline tests cannot replace:

- real `systemctl` behavior
- live `nft` ruleset application
- side effects from `sysctl --system` and `modprobe`
- real listener conflicts, real default routes, or distribution-specific differences

### 4. Contract changes in documentation must have matching validation

If a change modifies behavior promised by any of these documents:

- `config-file-contract.md`
- `installer-flow.md`
- `interaction-contract.md`
- `multi-external-boundary.md`

then corresponding tests should be added or updated at the same time. Do not change only the prose.

## Layered Coverage

### A. Config Model and Canonical Contract

Goal:

- ensure that `loha.conf` has only one canonical syntax
- ensure that the strict reader, canonical normalize, and full-rewrite writer agree on the result
- ensure that input shortcuts and removed historical fields do not leak into the persisted contract

Current coverage:

- `tests/test_config.py`
- `tests/test_runtime_binding.py`
- `tests/test_cli.py`

Currently protected highlights:

- the strict parser rejects `export`, space-separated assignment, removed historical fields, and missing conditional fields
- `config normalize` rewrites only canonical syntax and no longer absorbs shell-style legacy formats
- input shortcuts for `EXTERNAL_IFS`, `LISTEN_IPS`, and toggle-style `auto` are materialized before save
- the single-external product boundary is enforced at the config layer
- key ordering, full-file output, and round-tripping with materialized defaults stay stable in the canonical writer

Recommended next additions:

- finer-grained combination tests for explicit materialization of conditional fields

### B. Localization and Translation Runtime

Goal:

- ensure that `locales/*.toml` can be loaded, that the key set is complete, and that placeholders stay stable
- ensure that the installer, the CLI, and shared rendering helpers use the same runtime catalog

Current coverage:

- `tests/test_i18n.py`
- `tests/test_cli.py`
- `tests/test_install.py`

Currently protected highlights:

- locale-directory priority
- language-selector interaction
- display-name fallback
- runtime localization of key CLI and installer output

Recommended next additions:

- bilingual documentation still requires manual review for synchronization; there is currently no automated check for `README*.md` and `MANUAL*.md`

### C. Installer Precheck, Import, and Deployment

Goal:

- ensure that precheck, initial-config import, summary return paths, file deployment, and activation ordering remain stable

Current coverage:

- `tests/test_precheck.py`
- `tests/test_install.py`
- `tests/test_wizard.py`

Currently protected highlights:

- prechecks for root, kernel support, dependencies, and `ct label` capability
- choosing between repo config and system config during import
- fixed action numbers and return paths in the summary
- dry run, localization, deployment layout, and system-feature file writes
- call ordering for `systemctl daemon-reload`, `enable`, and `restart`
- when the install path fails during deploy, persist, or activation, the install flow rolls back installer-managed paths so it does not leave a half-installed state behind
- install persists `install_sync` into runtime metadata during install and uninstall finalization, instead of treating those lifecycle phases as invisible side effects
- service activation now happens after the installer releases the global control lock, so install does not deadlock against the loader's own control-plane lock
- when install fails after `sysctl --system`, the recovery flow runs `sysctl --system` again after restoring system-feature files so runtime state is brought back in line with the restored disk state
- when install fails during `systemctl restart loha.service`, recovery re-aligns the `systemd` manager and the preinstall enable and active state instead of merely restoring the unit file
- failed clean installs restore `run_dir` and runtime metadata alongside the rest of the installer-managed payload
- uninstall confirmation and best-effort cleanup flow

Recommended next additions:

- more transcript-level regression for failure paths
- live validation against different upstream firewall backends on real Linux

### D. Shared Wizard and Summary Contract

Goal:

- ensure that the shared installer and CLI config steps, Enter-to-accept semantics, and summary grouping stay stable

Current coverage:

- `tests/test_wizard.py`
- `tests/test_install.py`
- `tests/test_cli.py`

Currently protected highlights:

- pressing Enter accepts detected defaults
- cancel-token behavior
- returning from the summary to a specific section and then continuing to save
- `auto` shortcuts in imported config are materialized before entering the default-value flow
- the label-mode switch reuses the shared planner
- runtime-binding status lines appear in the summary

Recommended next additions:

- fuller transcript coverage for invalid-input retries
- section-by-section regression comparing installer and CLI behavior on shared fields

### E. CLI Control Surface and Interactive Commands

Goal:

- ensure stable behavior for `config`, `doctor`, `reload`, advanced menus, and the `rules.conf` editing path

Current coverage:

- `tests/test_cli.py`
- `tests/test_rules_tx.py`

Currently protected highlights:

- `config get/show/set/normalize`
- case and `-/_` variants for canonical keys
- the `AUTH_MODE` shared planner
- the `systemd` paths for `reload` and `reload --full`
- `history status/show/rollback`
- `config show --json` exposes control-plane revision, pending-action, and last-error state without scraping terminal text
- `reload --json`, `config history status/show --json`, and `config rollback --json` keep their machine-readable categories and revision/pending-action fields
- shared update paths for `rpfilter` and `conntrack`
- editor parsing, post-edit validation, and listener-conflict confirmation branches
- `rules.conf` syntax and validation failures are localized in human-facing CLI/TUI output
- `ct mark` dynamic detection output distinguishes static references from live conntrack observations
- `ct mark` static detection ignores LOHA-owned `loha_port_forwarder` / debug artifacts and does not misread LOHA clear masks as conflicts on the other candidate bits
- the main-menu rendered-rules view matches `loha rules render` instead of reusing a stale debug snapshot after `reload`
- the interactive menu reload action passes the active runtime locale through to shared apply helpers
- the current-state panel and submenu retry logic in advanced menus

Recommended next additions:

- fuller transcript tests for the main menu
- dedicated regression for diagnostic commands such as `rendered rules`
- prioritize shared-contract tests instead of continuing to expand presentation-layer abstraction

### F. Renderer, Loader, and Runtime Binding

Goal:

- ensure consistent behavior between rendered skeletons, hot reload versus full reload decisions, and runtime-binding interpretation

Current coverage:

- `tests/test_render.py`
- `tests/test_loader.py`
- `tests/test_runtime_binding.py`

Currently protected highlights:

- the ruleset starts with idempotent destruction
- rendering differences between the `mark` and `label` authorization paths
- hot swap is allowed when control state is unchanged
- when only the port-mapping set in `rules.conf` changes, control state stays stable
- renderer refuses conflicting duplicate `dnat_rules` keys instead of submitting them to nft
- when only the `LISTEN_IPS` set changes under the same `PRIMARY_EXTERNAL_IF`, hot swap still holds
- changes to primary values such as `DEFAULT_SNAT_IP` that affect skeleton `define` values force full reload
- switching `EXTERNAL_IFS` or `PRIMARY_EXTERNAL_IF` forces full reload
- changing authorization mode forces full reload
- if runtime-binding validation fails, the loader never enters `nft_apply`
- `check_only` does not write control state or debug rulesets
- composite live conntrack marks are reported with their overlapping candidate bits and raw sample values, so conflict output stays explainable
- loader CLI / `systemd` entry paths read `LOCALE` and localize success output instead of falling back to English defaults
- routine apply success messages stay concise and do not carry a version prefix
- materialization and state descriptions for `EXTERNAL_IFS`, `LISTEN_IPS`, and toggle shortcuts
- when `PRIMARY_EXTERNAL_IF` is explicit, `EXTERNAL_IFS=auto` and `LISTEN_IPS=auto` still resolve on that primary interface
- explicit `LISTEN_IPS` may not drift away from `PRIMARY_EXTERNAL_IF`
- runtime-binding output in doctor and summary

Recommended next additions:

- more golden-style assertions for complete ruleset combinations
- live host regression for `nft` apply and rollback

### G. Rules Transactions, History, and System Features

Goal:

- ensure predictable behavior for atomic `rules.conf` writes, config snapshots, rollback, and system-feature side effects

Current coverage:

- `tests/test_rules.py`
- `tests/test_rules_tx.py`
- `tests/test_history.py`
- `tests/test_system_features.py`
- `tests/test_install.py`

Currently protected highlights:

- locking and atomic rewrite for `rules.conf`
- global control-lock usage plus `state.json`, `txn/pending.json`, and `runtime_state.json` reconcile/drift visibility across config, rollback, install, and uninstall
- snapshot deduplication, recent-window reuse, and separate rollback checkpoints
- after `rollback --apply` fails, if automatic recovery succeeds, the system returns to the pre-rollback file state
- a rescue directory is preserved when rollback fails
- file rendering and status reporting for `rp_filter` and `conntrack`
- `RP_FILTER_MODE=system` is now explicitly frozen as coherent whenever LOHA's own sysctl file is no longer writing `rp_filter`; the system holding `rp_filter` at `0/1/2` must no longer be misreported by `doctor` as "still LOHA-managed"
- regression has been restored for the link between install apply and system-feature reporting: after install in `system/system` mode, `90-loha-forwarding.conf` keeps only `ip_forward`, conntrack tuning files are removed, and later status and doctor views should stay coherent
- file writes and cleanup for system-feature files during install and uninstall
- install and uninstall lifecycle state is surfaced through `install_sync` in runtime metadata instead of being invisible to diagnostics

Recommended next additions:

- real filesystem lock contention and long-held lock scenarios
- full live-host recovery coverage for rollback `--apply`

### H. Diagnostics and Final Aggregation

Goal:

- ensure that doctor's layered results, summary levels, and guidance semantics remain stable

Current coverage:

- `tests/test_doctor.py`
- `tests/test_cli.py`
- `tests/test_runtime_binding.py`

Currently protected highlights:

- layered checks for systemd, runtime sysctl, live nft, listener conflicts, runtime binding, and system features
- fail and warn counts in the summary
- guidance for live checks that require root
- `doctor` now interprets `systemd` and live `nft` state together: if the service is not running or the unit is missing, a missing table is coherent; only when the service is active and the table is missing does that become a real error
- runtime-binding violations cause doctor to fail
- runtime localization
- doctor plus `config show --json` surface control-plane pending actions such as `reload`, `sysctl_sync`, and `install_sync` instead of forcing callers to infer runtime drift from side effects alone

Recommended next additions:

- snapshot comparison of doctor output on real Linux hosts

### I. Repository-Level Smoke and Real-Environment Validation

Goal:

- provide one minimal, repeatable offline acceptance path for the current repository scope
- keep a shared template and latest record for real-host validation outside the public repository

Current coverage:

- `tests/test_smoke_flow.py`
- `scripts/run_smoke.sh`
- internally maintained real Linux validation records
- internally maintained real Linux validation templates

Currently protected highlights:

- a local, offline, repeatable baseline smoke flow for the repo
- key entry-point chaining in the current scope
- the first round of real Linux validation records

Recommended next additions:

- live validation records across more distributions and kernel versions

## Current Conclusion

As of 2026-03-26, the validation baseline in the current Python repository has converged from a historical shell-test list into:

1. `scripts/run_tests.sh` for full offline regression
2. `scripts/run_smoke.sh` for minimal smoke chaining
3. separate real Linux validation maintained as internal project docs with validation records and templates

As a result, when new features or contract changes are introduced, new tests should be added first within the current layered `tests/test_*.py` structure instead of reviving a parallel shell-test naming system.
