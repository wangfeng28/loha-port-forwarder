# LOHA Config File Contract

## Purpose

This document freezes the canonical file contract of `loha.conf`. It defines:

- which syntax counts as a valid persisted format
- which boundaries the reader and writer must each follow
- which non-canonical forms are rejected everywhere in the current repository

Related documents:

- [canonical-config-model.md](./canonical-config-model.md)
- [validation-matrix.md](./validation-matrix.md)

## Scope

This document covers only:

- `/etc/loha/loha.conf`

This document does not cover:

- the syntax of `rules.conf`
- shell runtime environment injection
- the file layout of historical snapshot directories

## Frozen Decisions

### 1. `loha.conf` allows only one canonical syntax

A valid config-key line must be:

```ini
KEY="VALUE"
```

Constraints:

- `KEY` uses uppercase letters, digits, and underscores
- no spaces are allowed around `=`
- values must always be wrapped in double quotes
- one line expresses exactly one key

### 2. The only non-key lines allowed are blank lines and comment lines

Allowed:

- blank lines
- full-line comments that start with `#`

Not promised to be preserved:

- arbitrary formatting
- inline comments at the end of a line
- shell-fragment-style comment layouts

### 3. The reader must be strict

The canonical reader must reject:

- `export KEY="VALUE"`
- `KEY = "VALUE"`
- `KEY=VALUE`
- duplicate keys
- missing quotes or unclosed quotes
- any other leftover shell syntax

The point of being strict here is not to make life harder for users. It is to prevent different consumers from reading the same file in different ways.

### 4. The writer must fully rewrite the file into canonical form

The writer is not responsible for "preserving as much of the old file as possible". Its job is to:

- read validated config state
- rewrite the entire `loha.conf` in a stable and predictable key order
- emit canonical syntax consistently

The writer must not:

- keep carrying old formats forward
- replace only the old lines it happens to recognize
- write historical format differences back into the new file

### 5. Non-canonical forms are rejected throughout the current repository

The current repository no longer includes a normalize-or-migrate path that absorbs old shell-style formats.

That means the following are all rejected instead of being silently "fixed up":

- `export KEY="VALUE"`
- `KEY = "VALUE"`
- `KEY=VALUE`

`loha config normalize` still exists, but its scope has narrowed to:

- rewriting a `loha.conf` that already uses canonical line syntax
- materializing shortcuts that still belong to the current input layer, such as `EXTERNAL_IFS="auto"` and `LISTEN_IPS="auto"`

It is no longer responsible for importing shell-style legacy formats.

### 6. Canonical files must not persist input-shortcut `auto`

For `loha.conf`, the following must not remain as long-term persisted results:

- `EXTERNAL_IFS=auto`
- `LISTEN_IPS=auto`
- toggle-style `auto` values used only to decide whether a recommended value was accepted

If an `auto` value represents a true mode semantic rather than an input shortcut, whether it may be persisted is defined separately by that field's own canonical semantics.

## Why This Narrowing Matters

If the reader is permissive, the writer is conservative, and different consumers each pick the format they happen to understand, you end up with cases like:

- the CLI reading one value
- the loader reading another value
- the installer importing yet another default

That is not just a formatting problem. It means the same file no longer has a single source of truth.

## Examples

### Valid Example

```ini
# LOHA canonical config
EXTERNAL_IFS="eth0"
PRIMARY_EXTERNAL_IF="eth0"
LISTEN_IPS="203.0.113.10,198.51.100.20"
DEFAULT_SNAT_IP="198.51.100.20"
LAN_IFS="br0"
LAN_NETS="192.168.10.0/24"
AUTH_MODE="mark"
DNAT_MARK="0x10000000"
```

### Invalid Example

```ini
export EXTERNAL_IFS="eth0"
LISTEN_IPS = "203.0.113.10"
DEFAULT_SNAT_IP=203.0.113.10
LISTEN_IPS="198.51.100.20"
```

Why it is invalid:

- it uses `export`
- it puts spaces around `=`
- values are not consistently quoted
- `LISTEN_IPS` is defined twice

## Current Conclusion

- canonical syntax is now frozen
- the rejection boundary of the strict reader is defined
- the responsibility of the full-rewrite writer is defined
- the rejection boundary for non-canonical forms in the current repository is defined
