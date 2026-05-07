use anyhow::anyhow;
use orchard::note::ExtractedNoteCommitment;
use serde::Serialize;
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus;
use zcash_protocol::consensus::Network;
use zcash_voting as voting;
use zip32::Scope;

/// Borrow a byte slice from a raw `(ptr, len)` pair.
///
/// When `len == 0`, returns an empty slice without reading `ptr`, so `ptr` may be null.
///
/// Centralizing the null + length check here lets every voting FFI byte input — strings,
/// JSON payloads, anything else — share one boundary contract instead of open-coding it
/// per call site. `str_from_ptr` now delegates to this helper.
///
/// # Safety
///
/// When `len > 0`, `ptr` must be non-null and valid for reads for `len` bytes, and the
/// memory must not be mutated for the duration of the call. The returned slice must not
/// outlive the underlying allocation.
pub(super) unsafe fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> anyhow::Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(anyhow!("FFI pointer is null but length is non-zero"));
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Parse a UTF-8 string from a raw pointer and length.
///
/// When `len == 0`, returns the empty string without reading `ptr`, so `ptr` may be null.
///
/// # Safety
///
/// Same contract as `bytes_from_ptr`.
pub(super) unsafe fn str_from_ptr(ptr: *const u8, len: usize) -> anyhow::Result<String> {
    let bytes = unsafe { bytes_from_ptr(ptr, len) }?;
    Ok(std::str::from_utf8(bytes)?.to_string())
}

/// Return JSON-serialized bytes as `*mut ffi::BoxedSlice`.
pub(super) fn json_to_boxed_slice<T: Serialize>(
    value: &T,
) -> anyhow::Result<*mut crate::ffi::BoxedSlice> {
    let json = serde_json::to_vec(value)?;
    Ok(crate::ffi::BoxedSlice::some(json))
}

/// Convert a librustzcash ReceivedNote (orchard) into zcash_voting's NoteInfo.
///
/// Requires the account's UFVK and network to compute the nullifier and
/// encode the UFVK string.
pub(super) fn received_note_to_note_info<P: consensus::Parameters>(
    note: &zcash_client_backend::wallet::ReceivedNote<
        zcash_client_sqlite::ReceivedNoteId,
        orchard::note::Note,
    >,
    ufvk: &UnifiedFullViewingKey,
    network: &P,
) -> anyhow::Result<voting::NoteInfo> {
    let orchard_note = note.note();
    let fvk = ufvk
        .orchard()
        .ok_or_else(|| anyhow!("UFVK has no Orchard component"))?;

    let nullifier = orchard_note.nullifier(fvk);
    // `voting::NoteInfo::commitment` is the wire-form (extracted) cmx, not the affine
    // note commitment, so the affine value is converted here before serialization.
    let cmx: ExtractedNoteCommitment = orchard_note.commitment().into();

    // Extract raw fields
    let diversifier = orchard_note.recipient().diversifier().as_array().to_vec();
    let value = orchard_note.value().inner();
    let rho = orchard_note.rho().to_bytes().to_vec();
    let rseed = orchard_note.rseed().as_bytes().to_vec();
    let position = u64::from(note.note_commitment_tree_position());
    let scope = match note.spending_key_scope() {
        Scope::External => 0u32,
        Scope::Internal => 1u32,
    };
    let ufvk_str = ufvk.encode(network);

    Ok(voting::NoteInfo {
        commitment: cmx.to_bytes().to_vec(),
        nullifier: nullifier.to_bytes().to_vec(),
        value,
        position,
        diversifier,
        rho,
        rseed,
        scope,
        ufvk_str,
    })
}

/// Open the wallet database.
pub(super) fn open_wallet_db(
    wallet_db_path: &str,
    network_id: u32,
) -> anyhow::Result<
    zcash_client_sqlite::WalletDb<rusqlite::Connection, Network, SystemClock, rand::rngs::OsRng>,
> {
    let network = crate::parse_network(network_id)?;
    zcash_client_sqlite::WalletDb::for_path(wallet_db_path, network, SystemClock, rand::rngs::OsRng)
        .map_err(|e| anyhow!("failed to open wallet DB: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_from_ptr_zero_len_accepts_null() {
        let bytes = unsafe { bytes_from_ptr(std::ptr::null(), 0) }.expect("empty");
        assert!(bytes.is_empty());
    }

    #[test]
    fn bytes_from_ptr_rejects_null_when_nonzero_len() {
        let err = unsafe { bytes_from_ptr(std::ptr::null(), 3) }.expect_err("null");
        assert!(err.to_string().contains("null"));
    }

    #[test]
    fn str_from_ptr_zero_len_accepts_null() {
        let s = unsafe { str_from_ptr(std::ptr::null(), 0) }.expect("empty");
        assert!(s.is_empty());
    }

    #[test]
    fn str_from_ptr_rejects_null_when_nonzero_len() {
        let err = unsafe { str_from_ptr(std::ptr::null(), 3) }.expect_err("null");
        assert!(err.to_string().contains("null"));
    }
}
