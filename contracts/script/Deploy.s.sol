// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {ZkCertRegistry} from "../src/ZkCertRegistry.sol";
import {IEAS, ISchemaRegistry} from "../src/interfaces/IEAS.sol";

/// Deploys ZkCertRegistry, registers the EAS schema (if new) and allowlists the keys in
/// config/dkim-keys.json.
///
///   PROGRAM_VKEY=$(cargo run --release -- vkey) forge script script/Deploy.s.sol \
///     --rpc-url $BASE_SEPOLIA_RPC_URL --private-key $PRIVATE_KEY --broadcast
///
/// Defaults are Base Sepolia: SP1 Groth16 gateway (sp1-contracts deployments/84532.json) and the
/// EAS predeploys. Override with SP1_GATEWAY, EAS, SCHEMA_REGISTRY for another chain.
contract Deploy is Script {
    /// One entry of config/dkim-keys.json. Fields in alphabetical order, as forge decodes JSON objects.
    struct KeyEntry {
        bytes32 keyHash;
        string name;
        uint256 platform;
        string record;
    }

    function run() external returns (ZkCertRegistry registry) {
        address gateway = vm.envOr("SP1_GATEWAY", address(0x397A5f7f3dBd538f23DE225B51f532c34448dA9B));
        address eas = vm.envOr("EAS", address(0x4200000000000000000000000000000000000021));
        address schemas = vm.envOr("SCHEMA_REGISTRY", address(0x4200000000000000000000000000000000000020));
        bytes32 vkey = vm.envBytes32("PROGRAM_VKEY");

        KeyEntry[] memory keys = loadKeys(vm.readFile(string.concat(vm.projectRoot(), "/../config/dkim-keys.json")));

        vm.startBroadcast();
        registry = new ZkCertRegistry(ISP1Verifier(gateway), vkey, IEAS(eas), vm.envOr("OWNER", msg.sender));
        bytes32 uid = registry.schemaUID();
        if (ISchemaRegistry(schemas).getSchema(uid).uid == bytes32(0)) {
            require(
                ISchemaRegistry(schemas).register(registry.SCHEMA(), address(0), false) == uid, "schema UID mismatch"
            );
        }
        for (uint256 i = 0; i < keys.length; i++) {
            registry.setKey(keys[i].keyHash, uint8(keys[i].platform));
        }
        vm.stopBroadcast();

        console.log("ZkCertRegistry", address(registry));
        console.log("schema UID");
        console.logBytes32(registry.schemaUID());
    }

    function loadKeys(string memory json) public pure returns (KeyEntry[] memory) {
        return abi.decode(vm.parseJson(json, ".keys"), (KeyEntry[]));
    }
}
