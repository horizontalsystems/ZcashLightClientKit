use super::db::{VotingDatabaseHandle, zcashlc_voting_db_open, zcashlc_voting_set_wallet_id};

pub(crate) fn open_memory_db() -> *mut VotingDatabaseHandle {
    let path = b":memory:";
    let db = unsafe { zcashlc_voting_db_open(path.as_ptr(), path.len()) };
    assert!(!db.is_null());

    let wallet = b"wallet";
    let code = unsafe { zcashlc_voting_set_wallet_id(db, wallet.as_ptr(), wallet.len()) };
    assert_eq!(code, 0);

    db
}

pub(crate) fn insert_round_and_bundle(db: *mut VotingDatabaseHandle, round_id: &str) {
    let handle = unsafe { db.as_ref() }.expect("db handle");
    let params = zcash_voting::VotingRoundParams {
        vote_round_id: round_id.to_string(),
        snapshot_height: 123,
        ea_pk: vec![7u8; 32],
        nc_root: vec![8u8; 32],
        nullifier_imt_root: vec![9u8; 32],
    };
    handle.db.init_round(&params, None).expect("insert round");

    let wallet_id = handle.db.wallet_id();
    let conn = handle.db.conn();
    conn.execute(
        "INSERT INTO bundles (round_id, wallet_id, bundle_index) VALUES (?1, ?2, ?3)",
        rusqlite::params![round_id, wallet_id, 0i64],
    )
    .expect("insert bundle");
}
