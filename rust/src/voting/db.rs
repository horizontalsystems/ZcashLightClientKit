use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting::storage::VotingDb;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::helpers::str_from_ptr;

/// Opaque handle wrapping the voting database.
pub struct VotingDatabaseHandle {
    pub(super) db: Arc<VotingDb>,
}

/// Open a voting database at the given path.
///
/// Returns an opaque `*mut VotingDatabaseHandle` on success, or null on error.
///
/// # Safety
///
/// - For the `(path, path_len)` byte argument: if `path_len > 0` then `path` must be
///   non-null and valid for reads for `path_len` bytes; if `path_len == 0`, `path` is
///   ignored.
/// - Call `zcashlc_voting_db_free` to free the returned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_open(
    path: *const u8,
    path_len: usize,
) -> *mut VotingDatabaseHandle {
    let res = catch_panic(|| {
        let path_str = unsafe { str_from_ptr(path, path_len) }?;
        let db = VotingDb::open(&path_str)
            .map_err(|e| anyhow!("Error opening voting database: {}", e))?;
        Ok(Box::into_raw(Box::new(VotingDatabaseHandle {
            db: Arc::new(db),
        })))
    });
    unwrap_exc_or_null(res)
}

/// Free a `VotingDatabaseHandle`.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer previously returned by
///   `zcashlc_voting_db_open` that has not already been freed.
/// - Calling this twice on the same non-null pointer, or on any pointer not obtained
///   from `zcashlc_voting_db_open`, is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_free(ptr: *mut VotingDatabaseHandle) {
    if !ptr.is_null() {
        let s: Box<VotingDatabaseHandle> = unsafe { Box::from_raw(ptr) };
        drop(s);
    }
}

/// Set the wallet identifier for all subsequent voting operations.
/// Must be called after `zcashlc_voting_db_open` and before any round operations.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For the `(wallet_id, wallet_id_len)` byte argument: if `wallet_id_len > 0` then
///   `wallet_id` must be non-null and valid for reads for `wallet_id_len` bytes; if
///   `wallet_id_len == 0`, `wallet_id` is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_set_wallet_id(
    db: *mut VotingDatabaseHandle,
    wallet_id: *const u8,
    wallet_id_len: usize,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let wallet_id_str = unsafe { str_from_ptr(wallet_id, wallet_id_len) }?;
        handle.db.set_wallet_id(&wallet_id_str);
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_open_rejects_invalid_utf8_path() {
        let invalid_path = [0xff];
        let handle = unsafe { zcashlc_voting_db_open(invalid_path.as_ptr(), invalid_path.len()) };
        assert!(handle.is_null());
    }

    #[test]
    fn db_free_accepts_null() {
        unsafe { zcashlc_voting_db_free(std::ptr::null_mut()) };
    }

    #[test]
    fn set_wallet_id_rejects_null_db() {
        let code = unsafe { zcashlc_voting_set_wallet_id(std::ptr::null_mut(), b"x".as_ptr(), 1) };
        assert_eq!(code, -1);
    }
}
