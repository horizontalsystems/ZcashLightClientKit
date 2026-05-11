/// Minimum seed length accepted by Zcash seed-based key derivation.
pub(super) const MIN_SEED_LEN: usize = 32;

/// Length of a Pallas seed fingerprint in bytes.
pub(super) const SEED_FINGERPRINT_LEN: usize = 32;

/// Canonical byte length for Pallas field elements used at the voting FFI boundary.
pub(super) const CANONICAL_FIELD_LEN: usize = 32;

/// Hex string length for canonical voting round identifiers.
pub(super) const VOTE_ROUND_ID_HEX_LEN: usize = CANONICAL_FIELD_LEN * 2;
