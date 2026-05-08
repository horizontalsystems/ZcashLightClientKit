//
//  VotingRustBackendTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

final class VotingRustBackendTests: XCTestCase {
    func test_computeShareNullifier_returnsExpectedValueForKnownFixture() throws {
        // Well-formed 32-byte fixtures.
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
        // fixture above. Update only if the upstream algorithm intentionally
        // changes. A mismatch otherwise indicates the FFI wrapper is feeding
        // arguments incorrectly or mangling the output.
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
}
