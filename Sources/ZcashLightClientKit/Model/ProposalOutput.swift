//
//  ProposalOutput.swift
//
//
//  Created on 27/10/2025
//

import Foundation

/// A data structure that describes a single payment output in a multi-recipient transaction proposal.
///
/// Each `ProposalOutput` specifies a recipient address, the amount to send, and an optional memo.
/// Multiple `ProposalOutput` instances can be combined into a single transaction proposal using
/// `Synchronizer.proposeTransfer(accountUUID:proposalOutputs:)`.
public struct ProposalOutput: Equatable {
    /// The recipient of this payment output
    public let recipient: Recipient
    
    /// The amount to send in this output, in zatoshis
    public let amount: Zatoshi
    
    /// Optional memo to attach to this output
    ///
    /// - Note: Must be `nil` when `recipient` is a transparent address, as transparent
    ///   transactions do not support memos. Sending a memo to a transparent address will
    ///   result in a `ZcashError.synchronizerSendMemoToTransparentAddress` error.
    public let memo: Memo?
    
    /// Creates a new proposal output
    ///
    /// - Parameters:
    ///   - recipient: The recipient of this payment
    ///   - amount: The amount to send in zatoshis
    ///   - memo: Optional memo (must be `nil` for transparent recipients)
    public init(recipient: Recipient, amount: Zatoshi, memo: Memo?) {
        self.recipient = recipient
        self.amount = amount
        self.memo = memo
    }
}
