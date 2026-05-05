use std::ffi::CString;
use std::fmt::Write as _;
use std::os::raw::c_char;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::unwrap_exc_or_null;

/// Compute the share reveal nullifier from client-known inputs.
///
/// Returns the 32-byte nullifier as a hex string (64 chars), or null on error.
///
/// # Safety
///
/// - `vote_commitment` must point to exactly 32 bytes.
/// - `primary_blind` must point to exactly 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_compute_share_nullifier(
    vote_commitment: *const u8,
    primary_blind: *const u8,
    share_index: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let vc = unsafe { std::slice::from_raw_parts(vote_commitment, 32) };
        let blind = unsafe { std::slice::from_raw_parts(primary_blind, 32) };

        let nullifier = voting::share_tracking::compute_share_nullifier(vc, share_index, blind)
            .map_err(|e| anyhow!("compute_share_nullifier failed: {}", e))?;

        // Fixed-width hex: one 64-char allocation instead of per-byte `format!` temporaries.
        let mut hex_str = String::with_capacity(64);
        for b in nullifier {
            write!(&mut hex_str, "{b:02x}").expect("writing to a String cannot fail");
        }
        let c_str = CString::new(hex_str).map_err(|e| anyhow!("null byte in hex string: {}", e))?;
        Ok(c_str.into_raw())
    });
    unwrap_exc_or_null(res)
}
