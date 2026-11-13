//! Strict check of an SDDL string: owner and every DACL entry must be Administrators or SYSTEM.
//! Anything else (Users, Everyone, Authenticated Users, CREATOR OWNER, unknown SIDs, deny
//! entries we do not model) fails. Locale independent: SDDL uses SIDs/aliases, not names.

const TRUSTED: [&str; 4] = ["BA", "SY", "S-1-5-18", "S-1-5-32-544"];

pub fn is_admin_only(sddl: &str) -> Result<(), String> {
    let sddl = sddl.trim();
    let owner = section(sddl, "O:").ok_or("no owner")?;
    if !TRUSTED.contains(&owner.as_str()) {
        return Err(format!("owner {owner} is not Administrators/SYSTEM"));
    }
    let dacl_start = sddl
        .find("D:")
        .ok_or("no DACL (null DACL grants everyone access)")?;
    let mut rest = &sddl[dacl_start + 2..];
    // Strip flags before the first '('.
    let first = rest
        .find('(')
        .ok_or("DACL has no entries (empty DACL is not a usable state file ACL)")?;
    rest = &rest[first..];
    // A following S: (SACL) section ends the DACL.
    let end = rest.find("S:").unwrap_or(rest.len());
    let rest = &rest[..end];
    let mut count = 0;
    for ace in rest.split('(').skip(1) {
        let ace = ace.trim_end_matches(')');
        let f: Vec<&str> = ace.split(';').collect();
        if f.len() < 6 {
            return Err(format!("malformed ACE ({ace})"));
        }
        if f[0] != "A" {
            return Err(format!("unsupported ACE type {}", f[0]));
        }
        if !TRUSTED.contains(&f[5]) {
            return Err(format!("trustee {} is not Administrators/SYSTEM", f[5]));
        }
        count += 1;
    }
    if count == 0 {
        return Err("DACL has no entries".into());
    }
    Ok(())
}

const TRUSTED_WRITERS: [&str; 6] = [
    "BA",
    "SY",
    "TI",
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
const READ_TOKENS: [&str; 7] = ["GR", "GX", "FR", "FX", "RC", "LC", "RP"];
/// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE (includes SYNCHRONIZE/READ_CONTROL).
const READ_MASK: u32 = 0x0012_00a9;

/// Verifies that nobody except Administrators/SYSTEM/TrustedInstaller can write or change
/// the object (read access for others is fine). Used for the directories that hold executables.
pub fn no_untrusted_write(sddl: &str) -> Result<(), String> {
    let sddl = sddl.trim();
    let owner = section(sddl, "O:").ok_or("no owner")?;
    if !TRUSTED_WRITERS.contains(&owner.as_str()) {
        return Err(format!("owner {owner} is not trusted"));
    }
    let d = sddl.find("D:").ok_or("no DACL (null DACL)")?;
    let rest = &sddl[d + 2..];
    let rest = &rest[rest.find('(').ok_or("empty DACL")?..];
    let rest = &rest[..rest.find("S:").unwrap_or(rest.len())];
    for ace in rest.split('(').skip(1) {
        let f: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
        if f.len() < 6 {
            return Err(format!("malformed ACE ({ace})"));
        }
        if f[0] != "A" {
            return Err(format!("unsupported ACE type {}", f[0]));
        }
        if TRUSTED_WRITERS.contains(&f[5]) {
            continue;
        }
        let rights = f[2];
        let read_only = if let Some(hex) = rights.strip_prefix("0x") {
            u32::from_str_radix(hex, 16)
                .map(|m| m & !READ_MASK == 0)
                .unwrap_or(false)
        } else {
            rights.as_bytes().chunks(2).all(|t| {
                std::str::from_utf8(t)
                    .map(|t| READ_TOKENS.contains(&t))
                    .unwrap_or(false)
            })
        };
        if !read_only {
            return Err(format!(
                "trustee {} has write-capable rights {rights}",
                f[5]
            ));
        }
    }
    Ok(())
}

fn section(s: &str, tag: &str) -> Option<String> {
    let i = s.find(tag)?;
    let rest = &s[i + tag.len()..];
    let end = rest
        .find([':', '('])
        .map(|p| {
            // Stop before the next section tag (e.g. "G:", "D:").
            if rest.as_bytes().get(p) == Some(&b':') {
                p.saturating_sub(1)
            } else {
                p
            }
        })
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_admin_system_only() {
        assert!(is_admin_only("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").is_ok());
        assert!(is_admin_only("O:SYG:SYD:P(A;;FA;;;BA)").is_ok());
    }

    #[test]
    fn rejects_users_everyone_and_foreign_owner() {
        assert!(is_admin_only("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)").is_err());
        assert!(is_admin_only("O:BAG:SYD:(A;;FA;;;WD)").is_err());
        assert!(is_admin_only("O:BAG:SYD:(A;;FA;;;AU)").is_err());
        assert!(is_admin_only("O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;BA)").is_err());
    }

    #[test]
    fn rejects_null_empty_and_malformed() {
        assert!(is_admin_only("O:BAG:SY").is_err());
        assert!(is_admin_only("O:BAG:SYD:").is_err());
        assert!(is_admin_only("garbage").is_err());
        assert!(is_admin_only("O:BAD:(A;;FA)").is_err());
    }

    #[test]
    fn program_files_style_dir_is_accepted_but_user_writable_is_not() {
        let pf = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;;FRFX;;;AC)";
        assert!(no_untrusted_write(pf).is_ok());
        assert!(no_untrusted_write("O:BAD:(A;;FA;;;BA)(A;OICI;0x1301bf;;;BU)").is_err());
        assert!(no_untrusted_write("O:BAD:(A;;FA;;;BA)(A;;FA;;;WD)").is_err());
        assert!(no_untrusted_write("O:S-1-5-21-1-2-3-1001D:(A;;FA;;;BA)").is_err());
    }

    #[test]
    fn rejects_deny_entries_we_do_not_model() {
        assert!(is_admin_only("O:BAD:(D;;FA;;;BU)(A;;FA;;;BA)").is_err());
    }
}
