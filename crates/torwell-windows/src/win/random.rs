//! OS CSPRNG via BCryptGenRandom with the system-preferred RNG.

use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

use crate::error::{Error, Result};

pub fn fill(buf: &mut [u8]) -> Result<()> {
    // SAFETY: `buf` is a valid mutable slice; a null algorithm handle with the flag selects the system RNG.
    let status = unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.0 == 0 {
        Ok(())
    } else {
        Err(Error::Mac(format!(
            "BCryptGenRandom failed: 0x{:08x}",
            status.0 as u32
        )))
    }
}
