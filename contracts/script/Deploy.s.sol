// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {ZkCertRegistry} from "../src/ZkCertRegistry.sol";
import {IEAS, ISchemaRegistry} from "../src/interfaces/IEAS.sol";

/// Deploys ZkCertRegistry accepting the program versions in config/program.json `accepted`, and
/// registers the EAS schema (if new).
contract Deploy is Script {
    function run() external returns (ZkCertRegistry registry) {
        address gateway = vm.envOr("SP1_GATEWAY", address(0x397A5f7f3dBd538f23DE225B51f532c34448dA9B));
        address eas = vm.envOr("EAS", address(0x4200000000000000000000000000000000000021));
        address schemas = vm.envOr("SCHEMA_REGISTRY", address(0x4200000000000000000000000000000000000020));
        bytes32[] memory vkeys = loadVKeys(vm.readFile(string.concat(vm.projectRoot(), "/../config/program.json")));
        require(vkeys.length > 0, "config/program.json accepts no program version");

        vm.startBroadcast();
        registry = new ZkCertRegistry(ISP1Verifier(gateway), vkeys, IEAS(eas), vm.envOr("OWNER", msg.sender));
        bytes32 uid = registry.schemaUID();
        if (ISchemaRegistry(schemas).getSchema(uid).uid == bytes32(0)) {
            require(
                ISchemaRegistry(schemas).register(registry.SCHEMA(), address(0), false) == uid, "schema UID mismatch"
            );
        }
        vm.stopBroadcast();

        console.log("ZkCertRegistry", address(registry));
        console.log("schema UID");
        console.logBytes32(registry.schemaUID());
    }

    function loadVKeys(string memory json) public pure returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(json, ".accepted");
    }
}
