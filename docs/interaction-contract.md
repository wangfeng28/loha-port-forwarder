# LOHA Interaction Contract

## Purpose

This document freezes the interaction contract for the installer, the shared config wizard, and the TUI menu system in the current Python implementation of LOHA.

## Scope

This document covers:

- the interactive install flow in `install.sh`
- the shared configuration wizard used by the installer and `loha config wizard`
- the TUI menu entered by running `loha` with no arguments

## Core Principles

### 1. Numeric menus come first

Interaction should prefer numeric menus except in the following cases:

- IPv4 address input
- IPv4 CIDR input
- comma-separated interface, address, or network lists
- manual interface input when auto-detection fails

### 2. Pressing Enter must perform the clearly displayed default action

- when the screen shows a recommended value, current value, or default value, pressing Enter means accept that value and continue
- when the screen is a pure navigation menu with no other default action, pressing Enter means go back one level
- when the screen is a `y/N` or `Y/n` confirmation prompt, pressing Enter means use the default answer shown in the prompt
- default actions should lean toward the safer side whenever possible

### 3. The meaning of `0` must stay stable

- top-level TUI main menu: `0 = exit`
- most submenus: `0 = go back`
- installer final confirmation page: `0 = cancel this installation`

### 4. Wording must describe result semantics

Current interaction copy should be centered around:

- the primary external interface
- the external IPv4 addresses used for exposure
- protection scope
- default egress NAT
- authorization mode

It should not center itself around internal key names or legacy field concepts.

### 5. Advanced parameters must be configurable both through the wizard and through dedicated menus

The following parameters must not exist only inside the installer or shared wizard flow:

- `rp_filter`
- `conntrack`
- authorization marking mode (`ct mark` / `ct label`)
- WAN-to-WAN
- TCP MSS clamp
- `COUNTER_MODE`
- strict internal source address validation and its dependent fields

The TUI Advanced Settings area must provide dedicated submenu entry points for them.

## Input Types

### `menu-single`

Used for:

- single-choice selection
- mode selection
- on/off selection
- final confirmation actions

Constraints:

- consecutive numeric choices
- recommended options are explicitly marked
- show `0` when back navigation is allowed
- in pure navigation submenus, pressing Enter returns to the previous level

### `menu-multi`

Used for:

- selecting multiple interfaces
- selecting multiple objects

Constraints:

- input format is comma-separated numeric choices such as `1,3`
- empty input means keep the current value only when a current value already exists

### `text-ipv4-list`

Used for:

- the list of external IPv4 addresses used for exposure

Constraints:

- multiple IPv4 addresses are separated by ASCII commas
- invalid IPv4 input must raise an error and keep the user on the current step

### `text-cidr-list`

Used for:

- internal networks
- protected networks
- default egress NAT networks

### `text-iface-list-fallback`

Used for:

- the manual interface-input fallback path after auto-detection fails

## Stable Current Conventions

### 1. Installer and CLI shared wizard

The installer and the CLI shared wizard currently share:

- field semantics
- default values
- validation rules
- the four-section summary structure

They are allowed to differ in the following ways:

- the installer has precheck and install-finalization stages
- the CLI shared wizard has the two-stage forwarding and gateway entry structure

### 2. Raw `rules.conf` editing entry

The raw `rules.conf` editing entry in the TUI is an advanced operation. Its contract is:

- show a short warning first
- require an explicit `y/N` confirmation
- pressing Enter or typing `n` returns to the previous level
- typing `y` is the only way to continue
- validate `rules.conf` automatically after the editor exits
- if validation fails, both the failure summary and the parse/validation detail should follow the active locale instead of falling back to raw English parser text

### 3. Confirmation style for high-risk changes

The current implementation keeps a small number of `y/n` exception paths, mainly for:

- risk confirmation
- confirmation for `reload` and full rebuild style actions
- uninstall confirmation

These are exceptions. They are not the regular input mode of the main wizard.

### 4. Interaction contract for switching authorization mode

- the `ct mark` path must keep both static and dynamic conflict detection
- when the runtime environment supports dynamic detection, choosing `ct mark` should first enter a detection phase
- during that detection phase, pressing Enter means stop detection and inspect the current result
- after detection stops, the flow moves to a choice stage with: apply the current suggested value, choose a different candidate, switch to `ct label`, or run detection again
- when conflicts are detected in the `ct mark` path, the UI should distinguish static nft/config references from live conntrack observations and show mark samples instead of only printing an undifferentiated bit list
- the static `ct mark` scan must ignore LOHA-owned control-plane artifacts such as the live `loha_port_forwarder` table and debug snapshot; LOHA must not self-report its own auth mark or clear-mask rules as external conflicts
- the `ct label` path currently performs only static conflict detection

### 5. Language-switch entry contract

- `Switch Language / Change Language` must be present in the main menu
- in the English UI, show only `Change Language`
- in non-English UIs, show localized text plus ` / Change Language`
- human-facing runtime status lines, including `reload` / full-apply success messages, must follow the active locale on every entry path, including `systemd` / loader and post-edit validation flows
- version display belongs to dedicated version surfaces such as `loha --version` or the fixed main-menu title, not to routine success prefixes

### 6. Rendered-rules inspection contract

- the main-menu rendered-rules preview entry must render from the current config and `rules.conf` at the moment the user opens it
- it should match `loha rules render`
- it must not prefer a stale debug snapshot over the current render after a hot-swap `reload`

## Directions We Must Not Revert

- do not make the main flow depend on English enum input again
- do not mechanically turn every screen into "Enter = go back"; Enter must always follow the default action shown on the current screen
- do not kick the user all the way back to a higher-level menu from continuous-operation pages in the TUI
