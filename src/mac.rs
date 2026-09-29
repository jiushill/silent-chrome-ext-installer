// Chrome on Windows stores a "protection key" (per-machine) used to HMAC
// `Secure Preferences` entries. On Windows 8+ Chrome encrypts this key with
// DPAPI (system scope), base64-encodes it, and stores it in `Local State`
// under `os_crypt.app_bound_encrypted_key` (newer builds) or
// `os_crypt.encrypted_key` (older builds).
//
// Encrypted key layout:
//   v10  / v10X  : "v10" + 4-byte big-endian version + DPAPI_SYSTEM ciphertext
//   legacy       : 0x01 + 16-byte IV + DPAPI ciphertext
//
// We decrypt with `CryptUnprotectData` (CRYPTPROTECT_SYSTEM) and feed the
// plaintext key into HMAC-SHA256 to sign each entry.

#[cfg(windows)]
fn unprotect(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::HLOCAL;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    // Try both flag combinations: legacy user-scope (CRYPTPROTECT_UI_FORBIDDEN=0x1),
    // then system-scope (CRYPTPROTECT_SYSTEM=0x2). Newer Chrome uses user-scope
    // DPAPI on `encrypted_key`.
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const CRYPTPROTECT_SYSTEM: u32 = 0x2;
    for flags in [CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_SYSTEM, 0u32] {
        unsafe {
            let mut in_data = CRYPT_INTEGER_BLOB {
                cbData: ciphertext.len() as u32,
                pbData: ciphertext.as_ptr() as *mut u8,
            };
            let mut out_data = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            let ok = CryptUnprotectData(
                &mut in_data,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                flags,
                &mut out_data,
            );
            if ok != 0 {
                let len = out_data.cbData as usize;
                let ptr = out_data.pbData;
                if ptr.is_null() || len == 0 {
                    anyhow::bail!("CryptUnprotectData returned empty");
                }
                let v = std::slice::from_raw_parts(ptr, len).to_vec();
                windows_sys::Win32::System::Memory::LocalFree(ptr as HLOCAL);
                eprintln!("[*] DPAPI succeeded with flags=0x{:x}", flags);
                return Ok(v);
            }
        }
    }
    anyhow::bail!("CryptUnprotectData failed under all flag combinations (Win32 error)")
}

#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("DPAPI only available on Windows")
}

/// Read Chrome's prefs key from `Local State`. Returns the raw plaintext bytes
/// (16 bytes typically).
pub fn chrome_prefs_key(user_data_dir: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use anyhow::{anyhow, bail, Context};
    use base64::Engine;

    let path = user_data_dir.join("Local State");
    let s = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&s)?;

    let osc = v.get("os_crypt")
        .and_then(|x| x.as_object())
        .ok_or_else(|| anyhow!("Local State has no os_crypt"))?;

    let (raw_b64, label) = if let Some(s) = osc.get("encrypted_key").and_then(|x| x.as_str()) {
        (s, "encrypted_key")
    } else if let Some(s) = osc.get("app_bound_encrypted_key").and_then(|x| x.as_str()) {
        (s, "app_bound_encrypted_key")
    } else {
        bail!("Local State has neither encrypted_key nor app_bound_encrypted_key");
    };

    let raw = base64::engine::general_purpose::STANDARD.decode(raw_b64)?;
    eprintln!("[*] using {} ({} bytes encrypted)", label, raw.len());

    let stripped: &[u8] = if raw.starts_with(b"DPAPI") {
        // Chrome v100+: 5-byte "DPAPI" prefix, then DPAPI ciphertext.
        // (Empirically: trailing bytes 01 00 00 are version/flags already
        // absorbed by DPAPI's CRC, not stripped.)
        &raw[5..]
    } else if raw.starts_with(b"v10") || raw.starts_with(b"v10X") {
        // Older Chrome: "v10" + 4-byte big-endian version
        &raw[7..]
    } else if raw.first() == Some(&0x01) {
        // Legacy: 0x01 prefix
        &raw[1..]
    } else {
        bail!("unknown prefs key format prefix bytes: {:02x?}", &raw[..raw.len().min(8)]);
    };

    let plain = unprotect(stripped)?;
    if plain.len() != 16 && plain.len() != 32 {
        eprintln!("[!] unexpected prefs key length: {}", plain.len());
    }
    Ok(plain)
}