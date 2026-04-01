# Contributing to LOHA Port Forwarder

Thanks for helping improve LOHA.

## Before You Start

- For small fixes, open a pull request directly.
- For larger feature work, behavior changes, or scope changes, open an issue first so we can align on direction before code lands.
- Keep pull requests focused. Small, reviewable changes move faster and are safer to merge.

## Development Setup

```bash
git clone https://github.com/wangfeng28/loha-port-forwarder.git
cd loha-port-forwarder
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

The current test suite runs with:

```bash
./scripts/run_tests.sh
```

## Pull Request Expectations

- Base routine changes on `main` unless a maintainer asks for a different target branch.
- Add or update tests for user-visible behavior, validation logic, rendering changes, and install-path changes.
- Update `README.md`, or `MANUAL.md`, or `MANUAL_zh_CN.md` when install steps, operator workflows, or product boundaries change.
- Keep command-line and JSON output changes deliberate. If behavior changes, call that out clearly in the pull request.

## Commit and Review Notes

- Use clear commit messages that explain the functional change.
- If the change affects install, reload, rollback, validation, or i18n behavior, mention that explicitly in the pull request summary.
- Maintainers may ask contributors to split broad changes before review.

## Release Model

- Tagged releases use the `vX.Y.Z` format.
- GitHub Actions builds the release archive, checksum file, and provenance attestations from the tagged commit.
- The public release assets are published from GitHub Releases.
