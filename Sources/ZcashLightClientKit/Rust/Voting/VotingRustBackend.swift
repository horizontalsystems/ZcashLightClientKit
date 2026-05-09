//
//  VotingRustBackend.swift
//  ZcashLightClientKit
//

import Foundation
import libzcashlc

// MARK: - Error

/// Error type for voting Rust backend operations.
public enum VotingRustBackendError: LocalizedError, Equatable {
    /// The voting database is already open.
    case databaseAlreadyOpen
    /// The voting database is not open.
    case databaseNotOpen
    /// A Rust error occurred.
    case rustError(String)
    /// Invalid data was received.
    case invalidData(String)

    public var errorDescription: String? {
        switch self {
        case .databaseAlreadyOpen:
            return "Voting database is already open."
        case .databaseNotOpen:
            return "Voting database is not open."
        case .rustError(let message):
            return "Voting backend error: \(message)"
        case .invalidData(let message):
            return "Invalid data: \(message)"
        }
    }
}

// MARK: - VotingRustBackend

/// Swift wrapper for the voting `libzcashlc` surface.
public enum VotingRustBackend {}

// MARK: - Share tracking

extension VotingRustBackend {
    /// Byte width of a Pallas base-field element as expected by the voting FFI.
    private static let fieldElementByteCount = 32

    /// Compute the nullifier for a vote share.
    ///
    /// - Parameters:
    ///   - voteCommitment: 32-byte canonical Pallas-base-field encoding.
    ///   - shareIndex: Position of the share within its vote.
    ///   - primaryBlind: 32-byte canonical Pallas-base-field encoding.
    /// - Returns: 32-byte nullifier as 64 lowercase hex characters.
    /// - Throws: `VotingRustBackendError.invalidData` if either byte array is not
    ///   exactly 32 bytes; `VotingRustBackendError.rustError` if the underlying
    ///   Rust computation fails (for example, non-canonical field encoding).
    public static func computeShareNullifier(
        voteCommitment: [UInt8],
        shareIndex: UInt32,
        primaryBlind: [UInt8]
    ) throws -> String {
        guard
            voteCommitment.count == fieldElementByteCount,
            primaryBlind.count == fieldElementByteCount
        else {
            throw VotingRustBackendError.invalidData(
                "voteCommitment and primaryBlind must each be exactly \(fieldElementByteCount) bytes"
            )
        }

        let ptr = voteCommitment.withUnsafeBufferPointer { vcBuf in
            primaryBlind.withUnsafeBufferPointer { blindBuf in
                zcashlc_voting_compute_share_nullifier(
                    vcBuf.baseAddress,
                    blindBuf.baseAddress,
                    shareIndex
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`compute_share_nullifier` failed")
            )
        }
        defer { zcashlc_string_free(ptr) }
        return String(cString: ptr)
    }
}

// MARK: - Private helpers

private extension VotingRustBackend {
    /// Reads the last error recorded by `libzcashlc` and clears it as a side
    /// effect, so subsequent failures do not surface a stale message.
    static func staticLastErrorMessage(fallback: String) -> String {
        let errorLen = zcashlc_last_error_length()
        defer { zcashlc_clear_last_error() }

        if errorLen > 0 {
            let error = UnsafeMutablePointer<Int8>.allocate(capacity: Int(errorLen))
            defer { error.deallocate() }
            zcashlc_error_message_utf8(error, errorLen)
            if let msg = String(validatingUTF8: error) {
                return msg
            }
        }
        return fallback
    }
}
