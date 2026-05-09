//
//  VotingRustBackendTests.swift
//  ZcashLightClientKitTests
//

import XCTest
import SQLite3
@testable import ZcashLightClientKit

final class VotingRustBackendTests: XCTestCase {
    private var dbPath: String?

    private enum RoundTripFixture {
        static let walletId = "test-wallet"
        static let roundId = "round"
        static let bundleIndex: UInt32 = 0
        static let proposalId: UInt32 = 1
        static let shareIndex0: UInt32 = 0
        static let shareIndex1: UInt32 = 1
        static let snapshotHeight: UInt64 = 1
        static let voteCommitmentTreePosition: UInt64 = 42
        static let delegationTxHash = "delegation-tx-hash"
        static let voteTxHash = "vote-tx-hash"
        static let commitmentBundleJson = #"{"vote_commitment":[1,2,3],"proposal_id":1}"#
        static let helperAURL = "https://helper-a.example"
        static let helperBURL = "https://helper-b.example"
        static let firstSubmitAt: UInt64 = 1000
        static let secondSubmitAt: UInt64 = 2000
        static let createdAt: Int64 = 1_000
        static let fieldElementByteCount = 32
        static let keystoneSignatureByteCount = 64
        static let diversifierByteCount = 11
        static let eligibleNoteValue: UInt64 = 13_000_000
        static let sqliteSuccessCode = SQLITE_OK
        static let sqliteDoneCode = SQLITE_DONE

        static let roundParameter = [UInt8](repeating: 0x07, count: fieldElementByteCount)
        static let keystoneSignature = [UInt8](repeating: 0x01, count: keystoneSignatureByteCount)
        static let pcztSighash = [UInt8](repeating: 0x02, count: fieldElementByteCount)
        static let randomizedKey = [UInt8](repeating: 0x03, count: fieldElementByteCount)
        static let shareNullifier = String(repeating: "dd", count: fieldElementByteCount)
        static let voteCommitment = [UInt8](repeating: 0xAA, count: fieldElementByteCount)
    }

    override func tearDown() {
        if let dbPath {
            try? FileManager.default.removeItem(atPath: dbPath)
        }
        dbPath = nil
        super.tearDown()
    }

    // MARK: - computeShareNullifier

    func test_computeShareNullifier_returnsExpectedValueForKnownFixture() throws {
        var voteCommitment = [UInt8](repeating: 0, count: 32)
        voteCommitment[0] = 0x01
        var primaryBlind = [UInt8](repeating: 0, count: 32)
        primaryBlind[0] = 0x03

        let nullifier = try VotingRustBackend.computeShareNullifier(
            voteCommitment: voteCommitment,
            shareIndex: 0,
            primaryBlind: primaryBlind
        )

        // Captured from the Rust reference implementation
        // (`zcash_voting::share_tracking::compute_share_nullifier`) for the
        // fixture above.
        XCTAssertEqual(
            nullifier,
            "058ffd2e1ba7acaf97b167accfb4ec141b91c0ee2a0f552631851ac97ca1e61d"
        )
    }

    func test_computeShareNullifier_throwsInvalidData_whenInputsAreNot32Bytes() {
        let valid = [UInt8](repeating: 0x01, count: 32)
        let tooShort = [UInt8](repeating: 0x01, count: 31)
        let tooLong = [UInt8](repeating: 0x01, count: 33)

        for (vc, blind, label) in [
            (tooShort, valid, "voteCommitment too short"),
            (tooLong, valid, "voteCommitment too long"),
            (valid, tooShort, "primaryBlind too short"),
            (valid, tooLong, "primaryBlind too long")
        ] {
            XCTAssertThrowsError(
                try VotingRustBackend.computeShareNullifier(
                    voteCommitment: vc,
                    shareIndex: 0,
                    primaryBlind: blind
                ),
                label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: - Database lifecycle

    func test_open_succeedsAndCreatesFile() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path)
        backend.close()

        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    func test_open_secondTime_throwsDatabaseAlreadyOpen() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path)
        defer { backend.close() }

        XCTAssertThrowsError(try backend.open(path: path)) { error in
            guard case VotingRustBackendError.databaseAlreadyOpen = error else {
                XCTFail("expected .databaseAlreadyOpen, got \(error)")
                return
            }
        }
    }

    func test_close_isIdempotent() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path)
        backend.close()
        backend.close() // second close must not crash

        // Re-opening after close must succeed.
        try backend.open(path: path)
        backend.close()
    }

    func test_close_waitsForInFlightDatabaseOperationBeforeFreeingHandle() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()
        try backend.open(path: path)

        let operationStarted = XCTestExpectation(description: "operation started")
        let operationFinished = XCTestExpectation(description: "operation finished")
        let releaseOperation = DispatchSemaphore(value: 0)
        let closeFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            do {
                try backend.withLockedHandleForTesting {
                    operationStarted.fulfill()
                    releaseOperation.wait()
                }
                operationFinished.fulfill()
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }

        wait(for: [operationStarted], timeout: 1.0)

        DispatchQueue.global().async {
            backend.close()
            closeFinished.signal()
        }

        XCTAssertEqual(
            closeFinished.wait(timeout: .now() + .milliseconds(100)),
            .timedOut,
            "`close()` returned while a database operation still held the handle"
        )

        releaseOperation.signal()
        wait(for: [operationFinished], timeout: 1.0)
        XCTAssertEqual(closeFinished.wait(timeout: .now() + .seconds(1)), .success)

        XCTAssertThrowsError(try backend.setWalletId("wallet-after-close")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    // MARK: - requireHandle gating

    func test_setWalletId_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.setWalletId("wallet")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_resetTreeClient_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.resetTreeClient()) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_generateVanWitness_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.generateVanWitness(roundId: "round1", bundleIndex: 0, anchorHeight: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    // MARK: - Foundation helpers

    func test_decomposeWeight_returnsFixedWidthBinaryDecomposition() throws {
        XCTAssertEqual(try VotingRustBackend.decomposeWeight(0).filter { $0 != 0 }, [])
        XCTAssertEqual(try VotingRustBackend.decomposeWeight(1).filter { $0 != 0 }, [1])
        XCTAssertEqual(try VotingRustBackend.decomposeWeight(8).filter { $0 != 0 }, [8])
        XCTAssertEqual(
            try VotingRustBackend.decomposeWeight(11).filter { $0 != 0 }.sorted(),
            [1, 2, 8]
        )
    }

    func test_warmProvingCaches_doesNotThrow() throws {
        XCTAssertNoThrow(try VotingRustBackend.warmProvingCaches())
        XCTAssertNoThrow(try VotingRustBackend.warmProvingCaches())
    }

    func test_generateDelegationInputs_rejectsShortSeeds() {
        let short = [UInt8](repeating: 0x01, count: 31)
        let valid = [UInt8](repeating: 0x02, count: 32)
        XCTAssertThrowsError(
            try VotingRustBackend.generateDelegationInputs(
                senderSeed: short,
                hotkeySeed: valid,
                networkId: 1,
                accountIndex: 0
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    func test_generateDelegationInputs_withFvk_rejectsBadLengths() {
        struct Case {
            let fvk: [UInt8]
            let hotkey: [UInt8]
            let fingerprint: [UInt8]
            let label: String
        }

        let validHotkey = [UInt8](repeating: 0x02, count: 32)
        let validFvk = [UInt8](repeating: 0x03, count: 96)
        let validFp = [UInt8](repeating: 0x04, count: 32)
        let cases: [Case] = [
            .init(fvk: [UInt8](repeating: 0, count: 95), hotkey: validHotkey, fingerprint: validFp, label: "fvk too short"),
            .init(fvk: validFvk, hotkey: [UInt8](repeating: 0, count: 31), fingerprint: validFp, label: "hotkey too short"),
            .init(fvk: validFvk, hotkey: validHotkey, fingerprint: [UInt8](repeating: 0, count: 31), label: "fingerprint too short")
        ]
        for testCase in cases {
            let fvk = testCase.fvk
            let hotkey = testCase.hotkey
            let fp = testCase.fingerprint
            let label = testCase.label
            XCTAssertThrowsError(
                try VotingRustBackend.generateDelegationInputs(
                    senderFvk: fvk,
                    hotkeySeed: hotkey,
                    networkId: 1,
                    seedFingerprint: fp
                ),
                label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    func test_extractOrchardFvk_invalidUfvk_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.extractOrchardFvk(ufvk: "not-a-ufvk", networkId: 1)
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_extractPcztSighash_emptyInput_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.extractPcztSighash(pczt: [])
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_validatePirProof_rejectsBadLengths() {
        struct Case {
            let root: [UInt8]
            let nfBounds: [UInt8]
            let path: [UInt8]
            let nullifier: [UInt8]
            let expectedRoot: [UInt8]
            let label: String
        }

        let valid32 = [UInt8](repeating: 0x01, count: 32)
        let valid96 = [UInt8](repeating: 0x02, count: 96)
        let valid928 = [UInt8](repeating: 0x03, count: 928)

        let bad31 = [UInt8](repeating: 0, count: 31)
        let bad95 = [UInt8](repeating: 0, count: 95)
        let bad927 = [UInt8](repeating: 0, count: 927)

        let cases: [Case] = [
            .init(
                root: bad31,
                nfBounds: valid96,
                path: valid928,
                nullifier: valid32,
                expectedRoot: valid32,
                label: "root too short"
            ),
            .init(
                root: valid32,
                nfBounds: bad95,
                path: valid928,
                nullifier: valid32,
                expectedRoot: valid32,
                label: "nfBounds too short"
            ),
            .init(
                root: valid32,
                nfBounds: valid96,
                path: bad927,
                nullifier: valid32,
                expectedRoot: valid32,
                label: "path too short"
            ),
            .init(
                root: valid32,
                nfBounds: valid96,
                path: valid928,
                nullifier: bad31,
                expectedRoot: valid32,
                label: "nullifier too short"
            ),
            .init(
                root: valid32,
                nfBounds: valid96,
                path: valid928,
                nullifier: valid32,
                expectedRoot: bad31,
                label: "expectedRoot too short"
            )
        ]
        for testCase in cases {
            let proof = VotingPirProof(
                root: testCase.root,
                nfBounds: testCase.nfBounds,
                leafPosition: 0,
                path: testCase.path,
                nullifier: testCase.nullifier,
                expectedRoot: testCase.expectedRoot
            )
            XCTAssertThrowsError(
                try VotingRustBackend.validatePirProof(proof),
                testCase.label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(testCase.label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: - Round lifecycle

    func test_initRound_andGetRoundState_roundTripPersistsParams() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: 32)
        try backend.initRound(
            roundId: "round-1",
            snapshotHeight: 1234,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let state = try backend.getRoundState(roundId: "round-1")
        XCTAssertEqual(state.roundId, "round-1")
        XCTAssertEqual(state.snapshotHeight, 1234)
        XCTAssertEqual(state.phase, .initialized)
        XCTAssertNil(state.hotkeyAddress)
        XCTAssertNil(state.delegatedWeight)
        XCTAssertFalse(state.proofGenerated)
    }

    func test_initRound_rejectsInvalidParamLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: 32)
        let short = [UInt8](repeating: 0x07, count: 31)

        XCTAssertThrowsError(
            try backend.initRound(
                roundId: "bad",
                snapshotHeight: 1,
                eaPublicKey: short,
                ncRoot: valid,
                nullifierImtRoot: valid
            )
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_listRounds_returnsEmpty_whenNoRoundsInitialized() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let rounds = try backend.listRounds()
        XCTAssertTrue(rounds.isEmpty)
    }

    func test_listRounds_returnsInitializedRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: 32)
        try backend.initRound(
            roundId: "round-1",
            snapshotHeight: 42,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )
        try backend.initRound(
            roundId: "round-2",
            snapshotHeight: 43,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let rounds = try backend.listRounds()
        XCTAssertEqual(rounds.count, 2)
        XCTAssertEqual(Set(rounds.map(\.roundId)), ["round-1", "round-2"])
    }

    func test_getVotes_returnsEmpty_forFreshRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: 32)
        try backend.initRound(
            roundId: "round",
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        XCTAssertTrue(try backend.getVotes(roundId: "round").isEmpty)
    }

    // MARK: - Recovery state

    func test_delegationTxHash_roundTrips() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: RoundTripFixture.roundId)

        XCTAssertNil(
            try backend.getDelegationTxHash(
                roundId: RoundTripFixture.roundId,
                bundleIndex: RoundTripFixture.bundleIndex
            )
        )

        try backend.storeDelegationTxHash(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            txHash: RoundTripFixture.delegationTxHash
        )

        XCTAssertEqual(
            try backend.getDelegationTxHash(
                roundId: RoundTripFixture.roundId,
                bundleIndex: RoundTripFixture.bundleIndex
            ),
            RoundTripFixture.delegationTxHash
        )
    }

    func test_storeDelegationTxHash_throwsRustError_whenBundleMissing() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.storeDelegationTxHash(roundId: "missing", bundleIndex: 0, txHash: "abc")
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_voteTxHash_roundTrips() throws {
        let backend = try makeReadyBackend(walletId: RoundTripFixture.walletId)
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: RoundTripFixture.roundId)
        try insertVoteRow(
            roundId: RoundTripFixture.roundId,
            walletId: RoundTripFixture.walletId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId
        )

        XCTAssertNil(
            try backend.getVoteTxHash(
                roundId: RoundTripFixture.roundId,
                bundleIndex: RoundTripFixture.bundleIndex,
                proposalId: RoundTripFixture.proposalId
            )
        )

        try backend.storeVoteTxHash(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId,
            txHash: RoundTripFixture.voteTxHash
        )

        XCTAssertEqual(
            try backend.getVoteTxHash(
                roundId: RoundTripFixture.roundId,
                bundleIndex: RoundTripFixture.bundleIndex,
                proposalId: RoundTripFixture.proposalId
            ),
            RoundTripFixture.voteTxHash
        )
    }

    func test_commitmentBundle_roundTrips() throws {
        let backend = try makeReadyBackend(walletId: RoundTripFixture.walletId)
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: RoundTripFixture.roundId)
        try insertVoteRow(
            roundId: RoundTripFixture.roundId,
            walletId: RoundTripFixture.walletId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId
        )

        XCTAssertNil(
            try backend.getCommitmentBundle(
                roundId: RoundTripFixture.roundId,
                bundleIndex: RoundTripFixture.bundleIndex,
                proposalId: RoundTripFixture.proposalId
            )
        )

        try backend.storeCommitmentBundle(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId,
            bundleJson: RoundTripFixture.commitmentBundleJson,
            voteCommitmentTreePosition: RoundTripFixture.voteCommitmentTreePosition
        )

        let stored = try XCTUnwrap(
            backend.getCommitmentBundle(
                roundId: RoundTripFixture.roundId,
                bundleIndex: RoundTripFixture.bundleIndex,
                proposalId: RoundTripFixture.proposalId
            )
        )
        XCTAssertEqual(stored.bundleJson, RoundTripFixture.commitmentBundleJson)
        XCTAssertEqual(stored.voteCommitmentTreePosition, RoundTripFixture.voteCommitmentTreePosition)
    }

    func test_keystoneSignature_roundTrips() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: RoundTripFixture.roundId)

        try backend.storeKeystoneSignature(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            sig: RoundTripFixture.keystoneSignature,
            sighash: RoundTripFixture.pcztSighash,
            randomizedKey: RoundTripFixture.randomizedKey
        )

        XCTAssertEqual(
            try backend.getKeystoneSignatures(roundId: RoundTripFixture.roundId),
            [
                VotingKeystoneSignatureRecord(
                    bundleIndex: RoundTripFixture.bundleIndex,
                    sig: RoundTripFixture.keystoneSignature,
                    sighash: RoundTripFixture.pcztSighash,
                    randomizedKey: RoundTripFixture.randomizedKey
                )
            ]
        )
    }

    func test_storeKeystoneSignature_rejectsBadLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: 32)
        try backend.initRound(
            roundId: "round",
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        struct Case {
            let sig: [UInt8]
            let sighash: [UInt8]
            let randomizedKey: [UInt8]
            let label: String
        }

        let validSig = [UInt8](repeating: 0x01, count: 64)
        let validSighash = [UInt8](repeating: 0x02, count: 32)
        let validRk = [UInt8](repeating: 0x03, count: 32)

        let cases: [Case] = [
            .init(sig: [UInt8](repeating: 0, count: 63), sighash: validSighash, randomizedKey: validRk, label: "sig too short"),
            .init(sig: validSig, sighash: [UInt8](repeating: 0, count: 31), randomizedKey: validRk, label: "sighash too short"),
            .init(sig: validSig, sighash: validSighash, randomizedKey: [UInt8](repeating: 0, count: 31), label: "rk too short")
        ]
        for testCase in cases {
            XCTAssertThrowsError(
                try backend.storeKeystoneSignature(
                    roundId: "round",
                    bundleIndex: 0,
                    sig: testCase.sig,
                    sighash: testCase.sighash,
                    randomizedKey: testCase.randomizedKey
                ),
                testCase.label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(testCase.label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    func test_getKeystoneSignatures_returnsEmpty_forFreshRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertTrue(try backend.getKeystoneSignatures(roundId: "missing").isEmpty)
    }

    func test_clearRecoveryState_isNoop_onMissingRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertNoThrow(try backend.clearRecoveryState(roundId: "missing"))
    }

    // MARK: - Share delegation tracking

    func test_shareDelegationLifecycle_roundTripsHexNullifier() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: RoundTripFixture.roundId)

        try backend.recordShareDelegation(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId,
            shareIndex: RoundTripFixture.shareIndex0,
            sentToURLs: [RoundTripFixture.helperAURL],
            nullifier: RoundTripFixture.shareNullifier,
            submitAt: RoundTripFixture.firstSubmitAt
        )
        try backend.recordShareDelegation(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId,
            shareIndex: RoundTripFixture.shareIndex1,
            sentToURLs: [RoundTripFixture.helperBURL],
            nullifier: RoundTripFixture.shareNullifier,
            submitAt: RoundTripFixture.secondSubmitAt
        )

        let all = try backend.getShareDelegations(roundId: RoundTripFixture.roundId)
        XCTAssertEqual(all.count, 2)

        let share0 = try XCTUnwrap(all.first { $0.shareIndex == RoundTripFixture.shareIndex0 })
        XCTAssertEqual(share0.roundId, RoundTripFixture.roundId)
        XCTAssertEqual(share0.bundleIndex, RoundTripFixture.bundleIndex)
        XCTAssertEqual(share0.proposalId, RoundTripFixture.proposalId)
        XCTAssertEqual(share0.sentToURLs, [RoundTripFixture.helperAURL])
        XCTAssertEqual(share0.nullifier, RoundTripFixture.shareNullifier)
        XCTAssertFalse(share0.confirmed)
        XCTAssertEqual(share0.submitAt, RoundTripFixture.firstSubmitAt)

        XCTAssertEqual(try backend.getUnconfirmedDelegations(roundId: RoundTripFixture.roundId).count, 2)

        try backend.markShareConfirmed(
            roundId: RoundTripFixture.roundId,
            bundleIndex: RoundTripFixture.bundleIndex,
            proposalId: RoundTripFixture.proposalId,
            shareIndex: RoundTripFixture.shareIndex0
        )

        let confirmedShare = try XCTUnwrap(
            backend.getShareDelegations(roundId: RoundTripFixture.roundId)
                .first { $0.shareIndex == RoundTripFixture.shareIndex0 }
        )
        XCTAssertTrue(confirmedShare.confirmed)

        let unconfirmed = try backend.getUnconfirmedDelegations(roundId: RoundTripFixture.roundId)
        XCTAssertEqual(unconfirmed.count, 1)
        XCTAssertEqual(unconfirmed[0].shareIndex, RoundTripFixture.shareIndex1)
    }

    func test_recordShareDelegation_rejectsInvalidNullifierLength() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let bad = String(repeating: "aa", count: 31)
        XCTAssertThrowsError(
            try backend.recordShareDelegation(
                roundId: "round",
                bundleIndex: 0,
                proposalId: 0,
                shareIndex: 0,
                sentToURLs: ["https://helper.example"],
                nullifier: bad,
                submitAt: 0
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    func test_getShareDelegations_returnsEmpty_forUnknownRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertTrue(try backend.getShareDelegations(roundId: "missing").isEmpty)
        XCTAssertTrue(try backend.getUnconfirmedDelegations(roundId: "missing").isEmpty)
    }

    // MARK: - Delegation workflow

    func test_setupBundles_returnsZero_forEmptyNotes() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: 32)
        try backend.initRound(
            roundId: "round",
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let result = try backend.setupBundles(roundId: "round", notes: [])
        XCTAssertEqual(result.bundleCount, 0)
        XCTAssertEqual(result.eligibleWeight, 0)
        XCTAssertEqual(try backend.getBundleCount(roundId: "round"), 0)
    }

    func test_buildPczt_rejectsInvalidSeedFingerprintLength() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let params = VotingBuildPcztParams(
            roundId: "round",
            bundleIndex: 0,
            notes: [],
            fvk: [UInt8](repeating: 0, count: 96),
            hotkeyRawAddress: [UInt8](repeating: 0, count: 43),
            consensusBranchId: 0,
            coinType: 0,
            seedFingerprint: [UInt8](repeating: 0, count: 31),
            accountIndex: 0,
            roundName: "Round",
            addressIndex: 0
        )
        XCTAssertThrowsError(try backend.buildPczt(params)) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    func test_getDelegationSubmissionWithKeystoneSig_rejectsBadLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.getDelegationSubmission(
                roundId: "round",
                bundleIndex: 0,
                keystoneSig: [UInt8](repeating: 0, count: 63),
                sighash: [UInt8](repeating: 0, count: 32)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
        XCTAssertThrowsError(
            try backend.getDelegationSubmission(
                roundId: "round",
                bundleIndex: 0,
                keystoneSig: [UInt8](repeating: 0, count: 64),
                sighash: [UInt8](repeating: 0, count: 31)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    // MARK: - Open database gating

    func test_initRound_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        let valid = [UInt8](repeating: 0, count: 32)
        XCTAssertThrowsError(
            try backend.initRound(
                roundId: "r",
                snapshotHeight: 0,
                eaPublicKey: valid,
                ncRoot: valid,
                nullifierImtRoot: valid
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_syncVoteTree_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.syncVoteTree(roundId: "round1", nodeUrl: "http://localhost")
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_listRounds_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.listRounds()) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_getRoundState_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.getRoundState(roundId: "r")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_setupBundles_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.setupBundles(roundId: "r", notes: [])) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_storeVanPosition_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.storeVanPosition(roundId: "r", bundleIndex: 0, position: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_precomputeDelegationPir_beforeOpen_throwsDatabaseNotOpen() async {
        let backend = VotingRustBackend()
        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: "round1",
                bundleIndex: 0,
                notes: [],
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                networkId: 1,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_storeKeystoneSignature_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.storeKeystoneSignature(
                roundId: "r",
                bundleIndex: 0,
                sig: [UInt8](repeating: 0, count: 64),
                sighash: [UInt8](repeating: 0, count: 32),
                randomizedKey: [UInt8](repeating: 0, count: 32)
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_buildAndProveDelegation_beforeOpen_throwsDatabaseNotOpen() async {
        let backend = VotingRustBackend()
        do {
            _ = try await backend.buildAndProveDelegation(
                roundId: "r",
                bundleIndex: 0,
                notes: [],
                hotkeyRawAddress: [UInt8](repeating: 0, count: 43),
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                networkId: 1,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - setWalletId

    func test_setWalletId_succeedsAfterOpen() throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        defer { backend.close() }

        XCTAssertNoThrow(try backend.setWalletId("wallet-id-1"))
        // Idempotent: setting again must succeed too.
        XCTAssertNoThrow(try backend.setWalletId("wallet-id-2"))
    }

    // MARK: - resetTreeClient

    func test_resetTreeClient_succeedsAfterOpen_withEmptyRoundId() throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        defer { backend.close() }

        // Empty round ID resets all in-memory tree clients; safe to call on a
        // fresh handle that has no clients yet.
        XCTAssertNoThrow(try backend.resetTreeClient())
    }

    // MARK: - precomputeDelegationPir resolver gating

    func test_precomputeDelegationPir_emptyEndpoints_throwsResolverError() async throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        defer { backend.close() }

        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: "round1",
                bundleIndex: 0,
                notes: [],
                pirEndpoints: [],
                expectedSnapshotHeight: 0,
                networkId: 1
            )
            XCTFail("expected PirSnapshotResolverError.noEndpointsConfigured")
        } catch PirSnapshotResolverError.noEndpointsConfigured {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - Helpers

    private func makeTempDbPath() -> String {
        let unique = ProcessInfo.processInfo.globallyUniqueString
        let path = "\(NSTemporaryDirectory())VotingRustBackendTests-\(unique).sqlite"
        dbPath = path
        return path
    }

    private func makeReadyBackend(walletId: String = RoundTripFixture.walletId) throws -> VotingRustBackend {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        try backend.setWalletId(walletId)
        return backend
    }

    private func createRoundWithBundle(
        _ backend: VotingRustBackend,
        roundId: String
    ) throws {
        try backend.initRound(
            roundId: roundId,
            snapshotHeight: RoundTripFixture.snapshotHeight,
            eaPublicKey: RoundTripFixture.roundParameter,
            ncRoot: RoundTripFixture.roundParameter,
            nullifierImtRoot: RoundTripFixture.roundParameter
        )

        let result = try backend.setupBundles(
            roundId: roundId,
            notes: [makeEligibleNote()]
        )
        XCTAssertEqual(result.bundleCount, 1)
    }

    private func makeEligibleNote() -> VotingNoteInfo {
        VotingNoteInfo(
            commitment: [UInt8](repeating: 0x01, count: RoundTripFixture.fieldElementByteCount),
            nullifier: [UInt8](repeating: 0x02, count: RoundTripFixture.fieldElementByteCount),
            value: RoundTripFixture.eligibleNoteValue,
            position: 0,
            diversifier: [UInt8](repeating: 0, count: RoundTripFixture.diversifierByteCount),
            rho: [UInt8](repeating: 0, count: RoundTripFixture.fieldElementByteCount),
            rseed: [UInt8](repeating: 0, count: RoundTripFixture.fieldElementByteCount),
            scope: 0,
            ufvkStr: ""
        )
    }

    private func insertVoteRow(
        roundId: String,
        walletId: String,
        bundleIndex: UInt32,
        proposalId: UInt32
    ) throws {
        let path = try XCTUnwrap(dbPath)
        var db: OpaquePointer?
        try requireSQLite(
            sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil),
            db,
            message: "open voting database"
        )
        defer { sqlite3_close(db) }

        let sql = """
        INSERT INTO votes (
            round_id,
            wallet_id,
            bundle_index,
            proposal_id,
            choice,
            commitment,
            created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        """
        var statement: OpaquePointer?
        try requireSQLite(
            sqlite3_prepare_v2(db, sql, -1, &statement, nil),
            db,
            message: "prepare vote insert"
        )
        defer { sqlite3_finalize(statement) }

        let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        let commitment = RoundTripFixture.voteCommitment

        try roundId.withCString { roundIdPointer in
            try requireSQLite(
                sqlite3_bind_text(statement, 1, roundIdPointer, -1, sqliteTransient),
                db,
                message: "bind round_id"
            )
        }
        try walletId.withCString { walletIdPointer in
            try requireSQLite(
                sqlite3_bind_text(statement, 2, walletIdPointer, -1, sqliteTransient),
                db,
                message: "bind wallet_id"
            )
        }
        try requireSQLite(
            sqlite3_bind_int64(statement, 3, sqlite3_int64(bundleIndex)),
            db,
            message: "bind bundle_index"
        )
        try requireSQLite(
            sqlite3_bind_int64(statement, 4, sqlite3_int64(proposalId)),
            db,
            message: "bind proposal_id"
        )
        try requireSQLite(
            sqlite3_bind_int64(statement, 5, 0),
            db,
            message: "bind choice"
        )
        try commitment.withUnsafeBufferPointer { buffer in
            try requireSQLite(
                sqlite3_bind_blob(statement, 6, buffer.baseAddress, Int32(buffer.count), sqliteTransient),
                db,
                message: "bind commitment"
            )
        }
        try requireSQLite(
            sqlite3_bind_int64(statement, 7, sqlite3_int64(RoundTripFixture.createdAt)),
            db,
            message: "bind created_at"
        )

        try requireSQLite(
            sqlite3_step(statement),
            db,
            expected: RoundTripFixture.sqliteDoneCode,
            message: "insert vote row"
        )
    }

    private func requireSQLite(
        _ code: Int32,
        _ db: OpaquePointer?,
        expected: Int32 = RoundTripFixture.sqliteSuccessCode,
        message: String
    ) throws {
        guard code == expected else {
            let details = db.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown SQLite error"
            throw NSError(
                domain: "VotingRustBackendTests.SQLite",
                code: Int(code),
                userInfo: [NSLocalizedDescriptionKey: "\(message): \(details)"]
            )
        }
    }
}

// MARK: - Test doubles

/// Probe stub that reports every endpoint as matching, so we can drive the
/// resolver into the FFI call without contacting a real server.
private struct AlwaysMatchingProbe: PirSnapshotProbing {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        PirSnapshotProbeOutcome(url: url, status: .matching(height: expectedSnapshotHeight))
    }
}

/// Probe stub used where endpoint probing must not happen.
private struct FailingProbe: PirSnapshotProbing {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        XCTFail("closed voting backend should fail before probing PIR endpoints")
        return PirSnapshotProbeOutcome(url: url, status: .matching(height: expectedSnapshotHeight))
    }
}
