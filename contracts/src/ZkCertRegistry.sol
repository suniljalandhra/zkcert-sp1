// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {AttestationRequest, AttestationRequestData, IEAS} from "./interfaces/IEAS.sol";

/// @notice Mirrors `PublicValues` in lib/src/lib.rs (ABI-encoded by the SP1 guest).
struct PublicValues {
    uint8 platform;
    bytes32 courseHash;
    string courseName;
    uint64 emailSignedAt;
    bytes32 dkimKeyHash;
    bytes32 nullifier;
    address wallet;
}

/// @title ZkCertRegistry
/// @notice Verifies zkCert SP1 proofs of Coursera/Udemy completion emails and records each
/// certificate once as an EAS attestation to the bound wallet.
/// @dev Trust: each zkCert program version compiles in its own DKIM key table (lib/src/keys.rs)
/// and rejects any other key inside the proof. Accepting a vkey therefore accepts that version's
/// key table; key rotation or revocation is a new program version plus `setVKey`. This contract
/// adds that the proof is for an accepted version, that only the bound wallet claims, and that
/// each certificate (nullifier) is claimed once across all versions.
contract ZkCertRegistry {
    /// EAS schema the attestations use (register it with exactly this string).
    string public constant SCHEMA =
        "uint8 platform,bytes32 courseHash,string courseName,uint64 emailSignedAt,bytes32 nullifier,bytes32 programVKey";

    ISP1Verifier public immutable verifier;
    IEAS public immutable eas;
    bytes32 public immutable schemaUID;

    address public owner;
    /// Program vkey => accepted. Owner-managed: add a version on release, remove it to retire it.
    mapping(bytes32 => bool) public acceptedVKeys;
    /// Nullifier => attestation UID; non-zero once claimed.
    mapping(bytes32 => bytes32) public claimed;

    event VKeySet(bytes32 indexed vkey, bool accepted);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Claimed(
        bytes32 indexed nullifier,
        address indexed wallet,
        uint8 platform,
        bytes32 courseHash,
        bytes32 programVKey,
        bytes32 uid
    );

    error NotOwner();
    error UnknownProgram(bytes32 vkey);
    error WrongWallet(address expected, address sender);
    error AlreadyClaimed(bytes32 nullifier, bytes32 uid);
    error ZeroAddress();
    error AttestationFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param _verifier The SP1VerifierGateway (routes by proof selector; never a fixed verifier).
    /// @param _vkeys Initially accepted program versions (config/program.json `accepted`).
    /// The EAS schema UID is derived from SCHEMA (EAS: keccak256(schema, resolver, revocable)) so
    /// the two cannot drift; Deploy.s.sol registers SCHEMA if it is not registered yet.
    constructor(ISP1Verifier _verifier, bytes32[] memory _vkeys, IEAS _eas, address _owner) {
        if (address(_verifier) == address(0) || address(_eas) == address(0) || _owner == address(0)) {
            revert ZeroAddress();
        }
        verifier = _verifier;
        eas = _eas;
        schemaUID = keccak256(abi.encodePacked(SCHEMA, address(0), false));
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
        for (uint256 i = 0; i < _vkeys.length; i++) {
            acceptedVKeys[_vkeys[i]] = true;
            emit VKeySet(_vkeys[i], true);
        }
    }

    /// @notice Accept or retire a program version. Retiring one stops new claims made with its
    /// proofs; attestations already issued are not revoked.
    function setVKey(bytes32 vkey, bool accepted) external onlyOwner {
        acceptedVKeys[vkey] = accepted;
        emit VKeySet(vkey, accepted);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Every check except the wallet and nullifier. Reverts if invalid; usable as an
    /// eth_call to check a bundle against this registry's accepted versions.
    function verify(bytes32 vkey, bytes calldata publicValues, bytes calldata proof)
        public
        view
        returns (PublicValues memory)
    {
        if (!acceptedVKeys[vkey]) revert UnknownProgram(vkey);
        verifier.verifyProof(vkey, publicValues, proof);
        return abi.decode(publicValues, (PublicValues));
    }

    /// @notice Verify and attest. Only the wallet bound inside the proof can claim, so a copied
    /// proof (front-running, sharing) is useless to anyone else.
    function claim(bytes32 vkey, bytes calldata publicValues, bytes calldata proof) external returns (bytes32 uid) {
        PublicValues memory v = verify(vkey, publicValues, proof);
        if (msg.sender != v.wallet) revert WrongWallet(v.wallet, msg.sender);
        if (claimed[v.nullifier] != bytes32(0)) revert AlreadyClaimed(v.nullifier, claimed[v.nullifier]);
        // Effects before the external call; EAS is trusted, but keep the order anyway.
        claimed[v.nullifier] = bytes32(uint256(1));
        uid = _attest(v, vkey);
        if (uid == bytes32(0)) revert AttestationFailed();
        claimed[v.nullifier] = uid;
        emit Claimed(v.nullifier, v.wallet, v.platform, v.courseHash, vkey, uid);
    }

    /// Separate frame: the request struct plus `claim`'s locals exceed the legacy stack limit.
    function _attest(PublicValues memory v, bytes32 vkey) internal returns (bytes32) {
        return eas.attest(
            AttestationRequest({
                schema: schemaUID,
                data: AttestationRequestData({
                    recipient: v.wallet,
                    expirationTime: 0,
                    revocable: false,
                    refUID: bytes32(0),
                    data: abi.encode(v.platform, v.courseHash, v.courseName, v.emailSignedAt, v.nullifier, vkey),
                    value: 0
                })
            })
        );
    }
}
