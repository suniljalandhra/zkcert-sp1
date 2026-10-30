// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {SP1Verifier as SP1VerifierGroth16} from "@sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";
import {ZkCertRegistry, PublicValues} from "../src/ZkCertRegistry.sol";
import {AttestationRequest, IEAS} from "../src/interfaces/IEAS.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// Calls back into the registry from attest(), as a malicious EAS would.
contract ReentrantEAS is IEAS {
    ZkCertRegistry public registry;
    bytes public pv;
    bool public reverted;

    function arm(ZkCertRegistry r, bytes memory v) external {
        registry = r;
        pv = v;
    }

    function attest(AttestationRequest calldata) external payable returns (bytes32) {
        try registry.claim(pv, "") {}
        catch {
            reverted = true;
        }
        return bytes32(uint256(7));
    }
}

contract ZeroUidEAS is IEAS {
    function attest(AttestationRequest calldata) external payable returns (bytes32) {
        return bytes32(0);
    }
}

contract MockEAS is IEAS {
    uint256 public count;
    AttestationRequest internal last;

    function attest(AttestationRequest calldata request) external payable returns (bytes32) {
        last = request;
        return keccak256(abi.encode(++count));
    }

    function lastData() external view returns (bytes memory, address) {
        return (last.data.data, last.data.recipient);
    }
}

/// Logic tests with SP1MockVerifier (accepts an empty proof for any public values).
contract ZkCertRegistryLogicTest is Test {
    bytes32 constant VKEY = bytes32(uint256(0xabc));
    bytes32 constant KEY = keccak256("udemy key");
    address constant WALLET = address(0xBEEF);

    ZkCertRegistry registry;
    MockEAS eas;

    function setUp() public {
        eas = new MockEAS();
        registry = new ZkCertRegistry(new SP1MockVerifier(), VKEY, eas, address(this));
        registry.setKey(KEY, 2);
    }

    function values(bytes32 key, uint8 platform, bytes32 nullifier, address wallet)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            PublicValues({
                platform: platform,
                courseHash: keccak256("Tally With Tax"),
                courseName: "Tally With Tax",
                completedAt: 0,
                dkimKeyHash: key,
                nullifier: nullifier,
                wallet: wallet
            })
        );
    }

    function test_ClaimAttestsToBoundWallet() public {
        vm.prank(WALLET);
        bytes32 uid = registry.claim(values(KEY, 2, bytes32("n1"), WALLET), "");
        assertEq(registry.claimed(bytes32("n1")), uid);
        (bytes memory data, address recipient) = eas.lastData();
        assertEq(recipient, WALLET);
        (uint8 platform,, string memory name,,) = abi.decode(data, (uint8, bytes32, string, uint64, bytes32));
        assertEq(platform, 2);
        assertEq(name, "Tally With Tax");
    }

    function test_RevertWhen_KeyNotAllowlisted() public {
        bytes32 other = keccak256("attacker key");
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.UnknownKey.selector, other, uint8(2)));
        registry.verify(values(other, 2, bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_KeyAllowlistedForOtherPlatform() public {
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.UnknownKey.selector, KEY, uint8(1)));
        registry.verify(values(KEY, 1, bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_PlatformZero() public {
        registry.setKey(KEY, 0);
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.UnknownKey.selector, KEY, uint8(0)));
        registry.verify(values(KEY, 0, bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_SenderIsNotBoundWallet() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.WrongWallet.selector, WALLET, address(0xBAD)));
        registry.claim(values(KEY, 2, bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_NullifierReused() public {
        vm.prank(WALLET);
        bytes32 uid = registry.claim(values(KEY, 2, bytes32("n1"), WALLET), "");
        // The same certificate proved again for a second wallet.
        address second = address(0xCAFE);
        vm.prank(second);
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.AlreadyClaimed.selector, bytes32("n1"), uid));
        registry.claim(values(KEY, 2, bytes32("n1"), second), "");
    }

    function test_RevertWhen_ProofInvalid() public {
        vm.expectRevert();
        registry.verify(values(KEY, 2, bytes32("n1"), WALLET), hex"01");
    }

    function test_RevertWhen_KeyRemoved() public {
        registry.setKey(KEY, 0);
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.UnknownKey.selector, KEY, uint8(2)));
        registry.verify(values(KEY, 2, bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_NonOwnerSetsKey() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(ZkCertRegistry.NotOwner.selector);
        registry.setKey(keccak256("attacker key"), 2);
    }

    function test_SchemaUidMatchesEasFormula() public view {
        assertEq(registry.schemaUID(), keccak256(abi.encodePacked(registry.SCHEMA(), address(0), false)));
    }

    function test_RevertWhen_InvalidPlatform() public {
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.InvalidPlatform.selector, uint8(3)));
        registry.setKey(KEY, 3);
    }

    function test_RevertWhen_ConstructorZeroAddress() public {
        SP1MockVerifier v = new SP1MockVerifier();
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        new ZkCertRegistry(ISP1Verifier(address(0)), VKEY, eas, address(this));
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        new ZkCertRegistry(v, VKEY, IEAS(address(0)), address(this));
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        new ZkCertRegistry(v, VKEY, eas, address(0));
    }

    function test_ReentrantClaimIsRejected() public {
        ReentrantEAS evil = new ReentrantEAS();
        ZkCertRegistry r = new ZkCertRegistry(new SP1MockVerifier(), VKEY, evil, address(this));
        r.setKey(KEY, 2);
        bytes memory pv = values(KEY, 2, bytes32("n1"), address(evil));
        evil.arm(r, pv);
        vm.prank(address(evil));
        r.claim(pv, "");
        // The nested claim saw the nullifier already marked and reverted.
        assertTrue(evil.reverted());
    }

    function test_RevertWhen_AttestationUidZero() public {
        ZkCertRegistry r = new ZkCertRegistry(new SP1MockVerifier(), VKEY, new ZeroUidEAS(), address(this));
        r.setKey(KEY, 2);
        vm.prank(WALLET);
        vm.expectRevert(ZkCertRegistry.AttestationFailed.selector);
        r.claim(values(KEY, 2, bytes32("n1"), WALLET), "");
    }

    function test_OwnershipTransfer() public {
        registry.transferOwnership(address(0x1));
        vm.expectRevert(ZkCertRegistry.NotOwner.selector);
        registry.setKey(KEY, 2);
        vm.prank(address(0x1));
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }
}

/// The real SP1 gateway + v6.1.0 Groth16 verifier, without a fixture: a mock or empty proof
/// (what SP1_PROVER=mock bundles contain) must never pass.
contract ZkCertRegistryGatewayTest is Test {
    ZkCertRegistry registry;
    bytes pv;

    function setUp() public {
        SP1VerifierGateway gateway = new SP1VerifierGateway(address(this));
        gateway.addRoute(address(new SP1VerifierGroth16()));
        registry = new ZkCertRegistry(gateway, bytes32(uint256(1)), new MockEAS(), address(this));
        registry.setKey(keccak256("k"), 2);
        pv = abi.encode(PublicValues(2, bytes32(0), "", 0, keccak256("k"), bytes32("n"), address(0xBEEF)));
    }

    function test_RevertWhen_EmptyProof() public {
        vm.expectRevert();
        registry.verify(pv, "");
    }

    function test_RevertWhen_UnknownVerifierSelector() public {
        vm.expectRevert();
        registry.verify(pv, hex"deadbeef");
    }

    function test_RevertWhen_GarbageGroth16Proof() public {
        bytes4 selector = bytes4(new SP1VerifierGroth16().VERIFIER_HASH());
        vm.expectRevert();
        registry.verify(pv, abi.encodePacked(selector, new bytes(11 * 32)));
    }
}

/// Deploy.s.sol reads config/dkim-keys.json correctly.
contract DeployScriptTest is Test {
    function test_LoadsAllowlist() public {
        Deploy d = new Deploy();
        Deploy.KeyEntry[] memory keys =
            d.loadKeys(vm.readFile(string.concat(vm.projectRoot(), "/../config/dkim-keys.json")));
        assertEq(keys.length, 2);
        assertEq(keys[0].platform, 1);
        assertEq(keys[0].keyHash, 0x34258a3d226293c85b11044d63a85aee881725f9df3400c5dec295b0ac5ce699);
        assertEq(keys[1].platform, 2);
        assertEq(keys[1].keyHash, 0x148b127e51c61a3f7d101bbf429c81e955ce720227d3c091e7b1b32f564a2451);
    }
}

/// End-to-end with a real Groth16 proof (`zkcert prove` on fixtures/redacted/synthetic-udemy.eml)
/// checked by the real SP1 v6.1.0 Groth16 verifier.
contract ZkCertRegistryProofTest is Test {
    ZkCertRegistry registry;
    MockEAS eas;
    bytes32 vkey;
    bytes proof;
    bytes publicValues;
    PublicValues v;

    bool hasFixture;

    /// Skips every test until the Groth16 fixture exists (it needs SP1_PROVER=network or a
    /// machine with more than 16 GB RAM; see README).
    modifier withFixture() {
        if (!hasFixture) {
            vm.skip(true);
        }
        _;
    }

    function setUp() public {
        string memory path = string.concat(vm.projectRoot(), "/src/fixtures/groth16-proof.json");
        hasFixture = vm.isFile(path);
        if (!hasFixture) return;
        string memory json = vm.readFile(path);
        vkey = vm.parseJsonBytes32(json, ".vkey");
        proof = vm.parseJsonBytes(json, ".proof");
        publicValues = vm.parseJsonBytes(json, ".publicValues");
        v = abi.decode(publicValues, (PublicValues));
        eas = new MockEAS();
        registry = new ZkCertRegistry(new SP1VerifierGroth16(), vkey, eas, address(this));
        registry.setKey(v.dkimKeyHash, v.platform);
    }

    function test_FixtureDecodes() public withFixture {
        assertEq(v.platform, 2);
        assertEq(v.courseHash, keccak256("Tally With Tax"));
        assertEq(v.wallet, 0x1234567890123456789012345678901234567890);
    }

    function test_RealProofClaims() public withFixture {
        vm.prank(v.wallet);
        registry.claim(publicValues, proof);
        assertTrue(registry.claimed(v.nullifier) != bytes32(0));
    }

    function test_RevertWhen_PublicValuesTampered() public withFixture {
        bytes memory tampered = abi.encode(
            PublicValues(v.platform, v.courseHash, "Harvard MBA", v.completedAt, v.dkimKeyHash, v.nullifier, v.wallet)
        );
        vm.expectRevert();
        registry.verify(tampered, proof);
    }

    function test_RevertWhen_WalletSwapped() public withFixture {
        bytes memory swapped = abi.encode(
            PublicValues(
                v.platform, v.courseHash, v.courseName, v.completedAt, v.dkimKeyHash, v.nullifier, address(0xBAD)
            )
        );
        vm.expectRevert();
        registry.verify(swapped, proof);
    }

    function test_RevertWhen_OtherProgramVKey() public withFixture {
        ZkCertRegistry other =
            new ZkCertRegistry(new SP1VerifierGroth16(), bytes32(uint256(vkey) ^ 1), eas, address(this));
        other.setKey(v.dkimKeyHash, v.platform);
        vm.expectRevert();
        other.verify(publicValues, proof);
    }

    function test_RevertWhen_ProofBitFlipped() public withFixture {
        bytes memory bad = bytes.concat(proof);
        bad[bad.length - 1] ^= 0x01;
        vm.expectRevert();
        registry.verify(publicValues, bad);
    }

    function test_ClaimGas() public withFixture {
        vm.prank(v.wallet);
        uint256 g = gasleft();
        registry.claim(publicValues, proof);
        emit log_named_uint("claim gas (incl. mock EAS)", g - gasleft());
    }
}
