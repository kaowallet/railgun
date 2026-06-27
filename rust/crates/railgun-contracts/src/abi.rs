//! alloy `sol!` bindings for the V2 + V3 RAILGUN contracts.
//!
//! Port of `src/abi/abi.ts` + the typechain interfaces (`RelayAdapt`,
//! `RailgunSmartWallet`, `PoseidonMerkleAccumulator`, `PoseidonMerkleVerifier`,
//! `TokenVault`). Only the V2/V3 functions + events the engine actually uses are
//! declared; V1/legacy ABIs are skipped per scope.
//!
//! These generate strongly-typed Rust structs for ABI encoding/decoding and
//! topic hashing (the same role the typechain `*__factory` files play in TS).
//! The crate uses them for RelayAdapt adapt-params hashing, `CallError` decoding,
//! and event decoding; the live RPC calls are issued by the caller's
//! [`crate::provider::EventProvider`].

use alloy::sol;

sol! {
    // ---- Shared structs (RailgunSmartWallet / RelayAdapt) ----
    #[derive(Debug)]
    struct TokenDataStruct {
        uint8 tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    #[derive(Debug)]
    struct CommitmentPreimageStruct {
        bytes32 npk;
        TokenDataStruct token;
        uint120 value;
    }

    #[derive(Debug)]
    struct ShieldCiphertextStruct {
        bytes32[3] encryptedBundle;
        bytes32 shieldKey;
    }

    #[derive(Debug)]
    struct ShieldRequestStruct {
        CommitmentPreimageStruct preimage;
        ShieldCiphertextStruct ciphertext;
    }

    #[derive(Debug)]
    struct CommitmentCiphertextStruct {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    // ---- RelayAdapt (V2) ----
    #[derive(Debug)]
    struct CallStruct {
        address to;
        bytes data;
        uint256 value;
    }

    #[derive(Debug)]
    struct ActionDataStruct {
        bytes31 random;
        bool requireSuccess;
        uint256 minGasLimit;
        CallStruct[] calls;
    }

    #[derive(Debug)]
    struct TokenTransferStruct {
        TokenDataStruct token;
        address to;
        uint256 value;
    }

    // The RelayAdapt `CallError` event — `getRelayAdaptCallError` filters on its
    // topic and ABI-decodes `(uint256 callIndex, bytes revertReason)`.
    #[derive(Debug)]
    event CallError(uint256 callIndex, bytes revertReason);

    // ---- RailgunSmartWallet (V2) events ----
    #[derive(Debug)]
    event Shield(
        uint256 treeNumber,
        uint256 startPosition,
        CommitmentPreimageStruct[] commitments,
        ShieldCiphertextStruct[] shieldCiphertext,
        uint256[] fees
    );

    #[derive(Debug)]
    event Transact(
        uint256 treeNumber,
        uint256 startPosition,
        bytes32[] hash,
        CommitmentCiphertextStruct[] ciphertext
    );

    #[derive(Debug)]
    event Unshield(
        address to,
        TokenDataStruct token,
        uint256 amount,
        uint256 fee
    );

    #[derive(Debug)]
    event Nullified(uint16 treeNumber, bytes32[] nullifier);

    // ---- RailgunSmartWallet (V2) read calls (eth_call) ----
    function merkleRoot() external view returns (bytes32);
    function rootHistory(uint256 treeNumber, bytes32 root) external view returns (bool);
    function nullifiers(uint256 treeNumber, bytes32 nullifier) external view returns (bool);
    function tokenIDMapping(bytes32 tokenHash) external view returns (TokenDataStruct);
    function fees() external view returns (uint128 shield, uint128 unshield, uint128 nft);

    // ---- RailgunSmartWallet (V2) `transact` + RelayAdapt `relay` function ABIs ----
    // Used by the validation `extract-transaction-data` path to ABI-decode the
    // `transact` / `relay` calldata into `TransactionStruct[]`. Mirrors the
    // typechain `TransactionStruct`, `BoundParamsStruct`, `SnarkProofStruct`.
    struct G1PointStruct {
        uint256 x;
        uint256 y;
    }

    struct G2PointStruct {
        uint256[2] x;
        uint256[2] y;
    }

    struct SnarkProofStruct {
        G1PointStruct a;
        G2PointStruct b;
        G1PointStruct c;
    }

    struct BoundParamsStruct {
        uint16 treeNumber;
        uint72 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertextStruct[] commitmentCiphertext;
    }

    struct TransactionStruct {
        SnarkProofStruct proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
        BoundParamsStruct boundParams;
        CommitmentPreimageStruct unshieldPreimage;
    }

    struct ActionDataStructV2 {
        bytes31 random;
        bool requireSuccess;
        uint256 minGasLimit;
        CallStruct[] calls;
    }

    // `transact(TransactionStruct[] _transactions)` — RailgunSmartWallet (V2).
    function transact(TransactionStruct[] _transactions) external payable;

    // `relay(TransactionStruct[] _transactions, ActionDataStructV2 _actionData)` — RelayAdapt (V2).
    function relay(TransactionStruct[] _transactions, ActionDataStructV2 _actionData) external payable returns (bool success);
}

// ---- V3: PoseidonMerkleAccumulator / Verifier / TokenVault ----
// Namespaced in its own module so the V3 `merkleRoot()` / `rootHistory(bytes32)`
// generated types do not collide with the V2 functions of the same name.
pub mod v3 {
    use alloy::sol;

    sol! {
        #[derive(Debug)]
        struct CommitmentCiphertextStructV3 {
            bytes ciphertext;
            bytes32 blindedSenderViewingKey;
            bytes32 blindedReceiverViewingKey;
        }

        // V3 PoseidonMerkleAccumulator emits a single batch `AccumulatorStateUpdate`
        // event. We declare the read calls the engine uses; full V3 event decoding
        // is tracked as a TODO (see crate::events).
        function merkleRoot() external view returns (bytes32);
        function rootHistory(bytes32 root) external view returns (bool);

        // V3 TokenVault
        function getTokenData(bytes32 tokenHash) external view returns (uint8 tokenType, address tokenAddress, uint256 tokenSubID);
    }
}
