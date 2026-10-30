// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// Minimal subset of the Ethereum Attestation Service interfaces (eas-contracts v1.x,
/// contracts/IEAS.sol and ISchemaRegistry.sol). Vendored to avoid pulling the whole repository.

struct AttestationRequestData {
    address recipient;
    uint64 expirationTime;
    bool revocable;
    bytes32 refUID;
    bytes data;
    uint256 value;
}

struct AttestationRequest {
    bytes32 schema;
    AttestationRequestData data;
}

interface IEAS {
    function attest(AttestationRequest calldata request) external payable returns (bytes32);
}

struct SchemaRecord {
    bytes32 uid;
    address resolver;
    bool revocable;
    string schema;
}

interface ISchemaRegistry {
    function getSchema(bytes32 uid) external view returns (SchemaRecord memory);
    function register(string calldata schema, address resolver, bool revocable) external returns (bytes32);
}
