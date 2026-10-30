// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";

/// Phase 0 smoke test: sp1-contracts resolves and the verifier interface is callable.
/// Replaced by ZkCertRegistry tests in Phase 4.
contract SP1SetupTest is Test {
    ISP1Verifier verifier;

    function setUp() public {
        verifier = new SP1MockVerifier();
    }

    function test_MockVerifierAcceptsEmptyProof() public view {
        verifier.verifyProof(bytes32(0), "", "");
    }

    function test_RevertWhen_MockProofNotEmpty() public {
        vm.expectRevert();
        verifier.verifyProof(bytes32(0), "", hex"01");
    }
}
