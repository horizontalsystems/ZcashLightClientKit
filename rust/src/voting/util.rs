use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::{parse_network, unwrap_exc_or_null};

use super::helpers::str_from_ptr;

// =============================================================================
// Free functions (no VotingDatabase needed)
// =============================================================================

/// Extract the 96-byte Orchard FVK from a UFVK string.
///
/// Returns the raw 96-byte Orchard FVK as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `ufvk_str` must be valid for reads of `ufvk_str_len` bytes (UTF-8 encoded).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_orchard_fvk_from_ufvk(
    ufvk_str: *const u8,
    ufvk_str_len: usize,
    network_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let ufvk_string = unsafe { str_from_ptr(ufvk_str, ufvk_str_len) }?;

        let network = parse_network(network_id)?;
        let ufvk = UnifiedFullViewingKey::decode(&network, &ufvk_string)
            .map_err(|e| anyhow!("failed to decode UFVK string: {}", e))?;

        let orchard_fvk = ufvk
            .orchard()
            .ok_or_else(|| anyhow!("UFVK has no Orchard component"))?;
        Ok(crate::ffi::BoxedSlice::some(
            orchard_fvk.to_bytes().to_vec(),
        ))
    });
    unwrap_exc_or_null(res)
}

#[cfg(test)]
mod tests {
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use super::*;
    use crate::{NETWORK_ID_MAINNET, NETWORK_ID_TESTNET};

    fn free(ptr: *mut crate::ffi::BoxedSlice) {
        unsafe { crate::ffi::zcashlc_free_boxed_slice(ptr) };
    }

    /// Build a deterministic, well-formed mainnet UFVK fixture and return its
    /// encoded string alongside its raw 96-byte Orchard FVK.
    fn derive_test_ufvk(network: Network) -> (String, [u8; 96]) {
        // 32 zero bytes is a valid seed length for `from_seed`. The exact value is
        // unimportant; we only need a deterministic, well-formed UFVK to round-trip
        // through the FFI.
        let seed = [0u8; 32];
        let account = zip32::AccountId::try_from(0).expect("account 0");
        let usk = UnifiedSpendingKey::from_seed(&network, &seed, account).expect("from_seed");
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network);
        let orchard_bytes = ufvk.orchard().expect("orchard present").to_bytes();
        (ufvk_str, orchard_bytes)
    }

    #[test]
    fn extract_orchard_fvk_returns_orchard_bytes_for_valid_mainnet_ufvk() {
        let (ufvk_str, expected) = derive_test_ufvk(Network::MainNetwork);

        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                ufvk_str.as_ptr(),
                ufvk_str.len(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!result.is_null(), "expected non-null BoxedSlice");

        let actual = unsafe { (*result).as_slice() }.to_vec();
        free(result);

        assert_eq!(actual.len(), 96, "Orchard FVK must be 96 bytes");
        assert_eq!(actual, expected.to_vec(), "FVK bytes must match");
    }

    #[test]
    fn extract_orchard_fvk_returns_orchard_bytes_for_valid_testnet_ufvk() {
        let (ufvk_str, expected) = derive_test_ufvk(Network::TestNetwork);

        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                ufvk_str.as_ptr(),
                ufvk_str.len(),
                NETWORK_ID_TESTNET,
            )
        };
        assert!(!result.is_null(), "expected non-null BoxedSlice");

        let actual = unsafe { (*result).as_slice() }.to_vec();
        free(result);

        assert_eq!(actual.len(), 96, "Orchard FVK must be 96 bytes");
        assert_eq!(actual, expected.to_vec(), "FVK bytes must match");
    }

    #[test]
    fn extract_orchard_fvk_rejects_mainnet_ufvk_with_testnet_network_id() {
        let (ufvk_str, _expected) = derive_test_ufvk(Network::MainNetwork);

        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                ufvk_str.as_ptr(),
                ufvk_str.len(),
                NETWORK_ID_TESTNET,
            )
        };
        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_null_pointer_with_nonzero_len() {
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(std::ptr::null(), 5, NETWORK_ID_MAINNET)
        };
        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_invalid_network_id() {
        let (ufvk_str, _expected) = derive_test_ufvk(Network::MainNetwork);
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(ufvk_str.as_ptr(), ufvk_str.len(), 99)
        };
        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_non_ufvk_string() {
        let bogus = b"not a ufvk";
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                bogus.as_ptr(),
                bogus.len(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_empty_input() {
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(std::ptr::null(), 0, NETWORK_ID_MAINNET)
        };
        assert!(result.is_null());
    }
}
