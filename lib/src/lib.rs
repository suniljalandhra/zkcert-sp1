pub mod canon;
pub mod dkim;
pub mod mime;
pub mod platform;
pub mod verify;

use alloy_sol_types::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    /// What a proof reveals. ABI-encoded by the guest; decoded by ZkCertRegistry.sol and the web UI.
    struct PublicValues {
        /// 1 = Coursera, 2 = Udemy.
        uint8 platform;
        /// keccak256 of the course name (whitespace-normalized UTF-8).
        bytes32 courseHash;
        /// The course name, or empty unless the user chose to disclose it.
        string courseName;
        /// DKIM t= rounded down to the UTC day (Unix seconds); 0 when there is no t= (Udemy).
        uint64 completedAt;
        /// keccak256 of the DKIM public key (SPKI DER); verifiers check it against an allowlist.
        bytes32 dkimKeyHash;
        /// keccak256("zkcert-v1", platform, courseHash, keccak256(lowercase To address)).
        bytes32 nullifier;
        /// The wallet this proof is bound to.
        address wallet;
    }
}
