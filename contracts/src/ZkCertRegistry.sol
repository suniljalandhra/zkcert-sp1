// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {AttestationRequest, AttestationRequestData, IEAS} from "./interfaces/IEAS.sol";

/// @notice Mirrors `PublicValues` in lib/src/lib.rs (ABI-encoded by the SP1 guest).
struct PublicValues {
    uint8 platform;
    bytes32 courseHash;
    string courseName;
    uint64 completedAt;
    bytes32 dkimKeyHash;
    bytes32 nullifier;
    address wallet;
}

/// @title ZkCertRegistry
/// @notice Verifies zkCert SP1 proofs of Coursera/Udemy completion emails and records each
/// certificate once as an EAS attestation to the bound wallet.
/// @dev Trust: the SP1 proof shows a DKIM signature by *some* key over a certificate email; this
/// contract adds that the key is one the owner has allowlisted for that platform, that the proof is
/// for the pinned zkCert program, and that each certificate (nullifier) is claimed once.
contract ZkCertRegistry {
    /// EAS schema the attestations use (register it with exactly this string).
    string public constant SCHEMA =
        "uint8 platform,bytes32 courseHash,string courseName,uint64 completedAt,bytes32 nullifier";

    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;
    IEAS public immutable eas;
    bytes32 public immutable schemaUID;

    address public owner;
    /// DKIM key hash => platform (1 Coursera, 2 Udemy); 0 = not allowed.
    mapping(bytes32 => uint8) public keyPlatform;
    /// Nullifier => attestation UID; non-zero once claimed.
    mapping(bytes32 => bytes32) public claimed;

    event KeySet(bytes32 indexed keyHash, uint8 platform);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Claimed(bytes32 indexed nullifier, address indexed wallet, uint8 platform, bytes32 courseHash, bytes32 uid);

    error NotOwner();
    error UnknownKey(bytes32 keyHash, uint8 platform);
    error WrongWallet(address expected, address sender);
    error AlreadyClaimed(bytes32 nullifier, bytes32 uid);
    error ZeroAddress();
    error InvalidPlatform(uint8 platform);
    error AttestationFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param _verifier The SP1VerifierGateway (routes by proof selector; never a fixed verifier).
    /// @param _programVKey The vkey pinned in config/program.json (`zkcert vkey`).
    /// The EAS schema UID is derived from SCHEMA (EAS: keccak256(schema, resolver, revocable)) so
    /// the two cannot drift; Deploy.s.sol registers SCHEMA if it is not registered yet.
    constructor(ISP1Verifier _verifier, bytes32 _programVKey, IEAS _eas, address _owner) {
        if (address(_verifier) == address(0) || address(_eas) == address(0) || _owner == address(0)) {
            revert ZeroAddress();
        }
        verifier = _verifier;
        programVKey = _programVKey;
        eas = _eas;
        schemaUID = keccak256(abi.encodePacked(SCHEMA, address(0), false));
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
    }

    /// @param platform 1 Coursera, 2 Udemy, 0 removes the key.
    function setKey(bytes32 keyHash, uint8 platform) external onlyOwner {
        if (platform > 2) revert InvalidPlatform(platform);
        keyPlatform[keyHash] = platform;
        emit KeySet(keyHash, platform);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Every check except the wallet and nullifier. Reverts if invalid; usable as an
    /// eth_call to check a bundle against this registry's allowlist.
    function verify(bytes calldata publicValues, bytes calldata proof) public view returns (PublicValues memory v) {
        verifier.verifyProof(programVKey, publicValues, proof);
        v = abi.decode(publicValues, (PublicValues));
        if (v.platform == 0 || keyPlatform[v.dkimKeyHash] != v.platform) {
            revert UnknownKey(v.dkimKeyHash, v.platform);
        }
    }

    /// @notice Verify and attest. Only the wallet bound inside the proof can claim, so a copied
    /// proof (front-running, sharing) is useless to anyone else.
    function claim(bytes calldata publicValues, bytes calldata proof) external returns (bytes32 uid) {
        PublicValues memory v = verify(publicValues, proof);
        if (msg.sender != v.wallet) revert WrongWallet(v.wallet, msg.sender);
        if (claimed[v.nullifier] != bytes32(0)) revert AlreadyClaimed(v.nullifier, claimed[v.nullifier]);
        // Effects before the external call; EAS is trusted, but keep the order anyway.
        claimed[v.nullifier] = bytes32(uint256(1));
        uid = eas.attest(
            AttestationRequest({
                schema: schemaUID,
                data: AttestationRequestData({
                    recipient: v.wallet,
                    expirationTime: 0,
                    revocable: false,
                    refUID: bytes32(0),
                    data: abi.encode(v.platform, v.courseHash, v.courseName, v.completedAt, v.nullifier),
                    value: 0
                })
            })
        );
        if (uid == bytes32(0)) revert AttestationFailed();
        claimed[v.nullifier] = uid;
        emit Claimed(v.nullifier, v.wallet, v.platform, v.courseHash, uid);
    }
}
