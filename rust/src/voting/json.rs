use serde::{Deserialize, Serialize};
use zcash_voting as voting;

/// JSON-serializable `NoteInfo`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonNoteInfo {
    pub commitment: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub value: u64,
    pub position: u64,
    pub diversifier: Vec<u8>,
    pub rho: Vec<u8>,
    pub rseed: Vec<u8>,
    pub scope: u32,
    pub ufvk_str: String,
}

impl From<JsonNoteInfo> for voting::NoteInfo {
    fn from(n: JsonNoteInfo) -> Self {
        Self {
            commitment: n.commitment,
            nullifier: n.nullifier,
            value: n.value,
            position: n.position,
            diversifier: n.diversifier,
            rho: n.rho,
            rseed: n.rseed,
            scope: n.scope,
            ufvk_str: n.ufvk_str,
        }
    }
}

impl From<voting::NoteInfo> for JsonNoteInfo {
    fn from(n: voting::NoteInfo) -> Self {
        Self {
            commitment: n.commitment,
            nullifier: n.nullifier,
            value: n.value,
            position: n.position,
            diversifier: n.diversifier,
            rho: n.rho,
            rseed: n.rseed,
            scope: n.scope,
            ufvk_str: n.ufvk_str,
        }
    }
}

/// JSON-serializable `DelegationPirPrecomputeResult`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationPirPrecomputeResult {
    pub cached_count: u32,
    pub fetched_count: u32,
}

impl From<voting::DelegationPirPrecomputeResult> for JsonDelegationPirPrecomputeResult {
    fn from(r: voting::DelegationPirPrecomputeResult) -> Self {
        Self {
            cached_count: r.cached_count,
            fetched_count: r.fetched_count,
        }
    }
}

/// JSON-serializable VanWitness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVanWitness {
    /// The authentication path for the witness.
    pub auth_path: Vec<Vec<u8>>,
    /// The position of the witness.
    pub position: u32,
    /// The anchor height of the witness.
    pub anchor_height: u32,
}

impl From<voting::tree_sync::VanWitness> for JsonVanWitness {
    fn from(w: voting::tree_sync::VanWitness) -> Self {
        Self {
            auth_path: w.auth_path.iter().map(|h| h.to_vec()).collect(),
            position: w.position,
            anchor_height: w.anchor_height,
        }
    }
}
