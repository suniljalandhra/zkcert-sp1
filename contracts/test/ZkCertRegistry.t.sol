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
    bytes32 public vkey;
    bytes public pv;
    bool public reverted;

    function arm(ZkCertRegistry r, bytes32 k, bytes memory v) external {
        registry = r;
        vkey = k;
        pv = v;
    }

    function attest(AttestationRequest calldata) external payable returns (bytes32) {
        try registry.claim(vkey, pv, "") {}
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
    bytes32 constant VKEY2 = bytes32(uint256(0xdef));
    bytes32 constant KEY = keccak256("udemy key");
    address constant WALLET = address(0xBEEF);

    ZkCertRegistry registry;
    MockEAS eas;

    function one(bytes32 vkey) internal pure returns (bytes32[] memory a) {
        a = new bytes32[](1);
        a[0] = vkey;
    }

    function setUp() public {
        eas = new MockEAS();
        registry = new ZkCertRegistry(new SP1MockVerifier(), one(VKEY), eas, address(this));
    }

    function values(bytes32 nullifier, address wallet) internal pure returns (bytes memory) {
        return abi.encode(
            PublicValues({
                platform: 2,
                courseHash: keccak256("Tally With Tax"),
                courseName: "Tally With Tax",
                emailSignedAt: 0,
                dkimKeyHash: KEY,
                nullifier: nullifier,
                wallet: wallet
            })
        );
    }

    function test_ClaimAttestsToBoundWallet() public {
        vm.prank(WALLET);
        bytes32 uid = registry.claim(VKEY, values(bytes32("n1"), WALLET), "");
        assertEq(registry.claimed(bytes32("n1")), uid);
        (bytes memory data, address recipient) = eas.lastData();
        assertEq(recipient, WALLET);
        (uint8 platform,, string memory name,,, bytes32 programVKey) =
            abi.decode(data, (uint8, bytes32, string, uint64, bytes32, bytes32));
        assertEq(platform, 2);
        assertEq(name, "Tally With Tax");
        assertEq(programVKey, VKEY);
    }

    function test_RevertWhen_VKeyNotAccepted() public {
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.UnknownProgram.selector, VKEY2));
        registry.verify(VKEY2, values(bytes32("n1"), WALLET), "");
    }

    function test_AddedVKeyIsAccepted() public {
        registry.setVKey(VKEY2, true);
        vm.prank(WALLET);
        registry.claim(VKEY2, values(bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_VKeyRetired() public {
        registry.setVKey(VKEY, false);
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.UnknownProgram.selector, VKEY));
        registry.verify(VKEY, values(bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_NonOwnerSetsVKey() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(ZkCertRegistry.NotOwner.selector);
        registry.setVKey(keccak256("attacker program"), true);
    }

    function test_ConstructorAcceptsAllGivenVKeys() public {
        bytes32[] memory both = new bytes32[](2);
        (both[0], both[1]) = (VKEY, VKEY2);
        ZkCertRegistry r = new ZkCertRegistry(new SP1MockVerifier(), both, eas, address(this));
        assertTrue(r.acceptedVKeys(VKEY) && r.acceptedVKeys(VKEY2));
        assertFalse(r.acceptedVKeys(bytes32(uint256(1))));
    }

    function test_RevertWhen_SenderIsNotBoundWallet() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.WrongWallet.selector, WALLET, address(0xBAD)));
        registry.claim(VKEY, values(bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_NullifierReused() public {
        vm.prank(WALLET);
        bytes32 uid = registry.claim(VKEY, values(bytes32("n1"), WALLET), "");
        // The same certificate proved again for a second wallet.
        address second = address(0xCAFE);
        vm.prank(second);
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.AlreadyClaimed.selector, bytes32("n1"), uid));
        registry.claim(VKEY, values(bytes32("n1"), second), "");
    }

    function test_RevertWhen_NullifierReusedUnderNewProgramVersion() public {
        // Rotating the program must not reopen certificates claimed under the old one.
        vm.prank(WALLET);
        bytes32 uid = registry.claim(VKEY, values(bytes32("n1"), WALLET), "");
        registry.setVKey(VKEY2, true);
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(ZkCertRegistry.AlreadyClaimed.selector, bytes32("n1"), uid));
        registry.claim(VKEY2, values(bytes32("n1"), WALLET), "");
    }

    function test_RevertWhen_ProofInvalid() public {
        vm.expectRevert();
        registry.verify(VKEY, values(bytes32("n1"), WALLET), hex"01");
    }

    function test_SchemaUidMatchesEasFormula() public view {
        assertEq(registry.schemaUID(), keccak256(abi.encodePacked(registry.SCHEMA(), address(0), false)));
    }

    function test_RevertWhen_ConstructorZeroAddress() public {
        SP1MockVerifier v = new SP1MockVerifier();
        bytes32[] memory vk = one(VKEY);
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        new ZkCertRegistry(ISP1Verifier(address(0)), vk, eas, address(this));
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        new ZkCertRegistry(v, vk, IEAS(address(0)), address(this));
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        new ZkCertRegistry(v, vk, eas, address(0));
    }

    function test_ReentrantClaimIsRejected() public {
        ReentrantEAS evil = new ReentrantEAS();
        ZkCertRegistry r = new ZkCertRegistry(new SP1MockVerifier(), one(VKEY), evil, address(this));
        bytes memory pv = values(bytes32("n1"), address(evil));
        evil.arm(r, VKEY, pv);
        vm.prank(address(evil));
        r.claim(VKEY, pv, "");
        // The nested claim saw the nullifier already marked and reverted.
        assertTrue(evil.reverted());
    }

    function test_RevertWhen_AttestationUidZero() public {
        ZkCertRegistry r = new ZkCertRegistry(new SP1MockVerifier(), one(VKEY), new ZeroUidEAS(), address(this));
        vm.prank(WALLET);
        vm.expectRevert(ZkCertRegistry.AttestationFailed.selector);
        r.claim(VKEY, values(bytes32("n1"), WALLET), "");
    }

    function test_OwnershipTransfer() public {
        registry.transferOwnership(address(0x1));
        vm.expectRevert(ZkCertRegistry.NotOwner.selector);
        registry.setVKey(VKEY2, true);
        vm.prank(address(0x1));
        vm.expectRevert(ZkCertRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }
}

/// The real SP1 gateway + v6.1.0 Groth16 verifier, without a fixture: a mock or empty proof (what
/// SP1_PROVER=mock bundles contain) must never pass.
contract ZkCertRegistryGatewayTest is Test {
    ZkCertRegistry registry;
    bytes32 constant VKEY = bytes32(uint256(1));
    bytes pv;

    function setUp() public {
        SP1VerifierGateway gateway = new SP1VerifierGateway(address(this));
        gateway.addRoute(address(new SP1VerifierGroth16()));
        bytes32[] memory vk = new bytes32[](1);
        vk[0] = VKEY;
        registry = new ZkCertRegistry(gateway, vk, new MockEAS(), address(this));
        pv = abi.encode(PublicValues(2, bytes32(0), "", 0, keccak256("k"), bytes32("n"), address(0xBEEF)));
    }

    function test_RevertWhen_EmptyProof() public {
        vm.expectRevert();
        registry.verify(VKEY, pv, "");
    }

    function test_RevertWhen_UnknownVerifierSelector() public {
        vm.expectRevert();
        registry.verify(VKEY, pv, hex"deadbeef");
    }

    function test_RevertWhen_GarbageGroth16Proof() public {
        bytes4 selector = bytes4(new SP1VerifierGroth16().VERIFIER_HASH());
        vm.expectRevert();
        registry.verify(VKEY, pv, abi.encodePacked(selector, new bytes(11 * 32)));
    }
}

/// Deploy.s.sol reads config/program.json correctly.
contract DeployScriptTest is Test {
    function test_LoadsAcceptedVKeys() public {
        Deploy d = new Deploy();
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../config/program.json"));
        bytes32[] memory vkeys = d.loadVKeys(json);
        assertGt(vkeys.length, 0);
        bytes32 current = vm.parseJsonBytes32(json, ".vkey");
        bool found;
        for (uint256 i = 0; i < vkeys.length; i++) {
            found = found || vkeys[i] == current;
        }
        assertTrue(found, "current vkey is not accepted");
    }
}

/// End-to-end with a real Groth16 proof of a real, allowlisted email (`zkcert prove`, see README)
/// checked by the real SP1 v6.1.0 Groth16 verifier.
contract ZkCertRegistryProofTest is Test {
    ZkCertRegistry registry;
    MockEAS eas;
    bytes32 vkey;
    bytes proof;
    bytes publicValues;
    PublicValues v;

    bool hasFixture;

    /// Skips every test until the Groth16 fixture exists (it needs SP1_PROVER=network or a machine
    /// with more than 16 GB RAM; see README).
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
        // A fixture from a retired program version (e.g. one without the key table) must not pass.
        bytes32[] memory accepted = vm.parseJsonBytes32Array(
            vm.readFile(string.concat(vm.projectRoot(), "/../config/program.json")), ".accepted"
        );
        bool ok;
        for (uint256 i = 0; i < accepted.length; i++) {
            ok = ok || accepted[i] == vkey;
        }
        require(ok, "fixture vkey is not an accepted program version (config/program.json)");
        eas = new MockEAS();
        bytes32[] memory vk = new bytes32[](1);
        vk[0] = vkey;
        registry = new ZkCertRegistry(new SP1VerifierGroth16(), vk, eas, address(this));
    }

    function test_FixtureDecodes() public withFixture {
        assertTrue(v.platform == 1 || v.platform == 2);
        assertTrue(v.wallet != address(0));
    }

    function test_RealProofClaims() public withFixture {
        vm.prank(v.wallet);
        registry.claim(vkey, publicValues, proof);
        assertTrue(registry.claimed(v.nullifier) != bytes32(0));
    }

    function test_RevertWhen_PublicValuesTampered() public withFixture {
        bytes memory tampered = abi.encode(
            PublicValues(v.platform, v.courseHash, "Harvard MBA", v.emailSignedAt, v.dkimKeyHash, v.nullifier, v.wallet)
        );
        vm.expectRevert();
        registry.verify(vkey, tampered, proof);
    }

    function test_RevertWhen_WalletSwapped() public withFixture {
        bytes memory swapped = abi.encode(
            PublicValues(
                v.platform, v.courseHash, v.courseName, v.emailSignedAt, v.dkimKeyHash, v.nullifier, address(0xBAD)
            )
        );
        vm.expectRevert();
        registry.verify(vkey, swapped, proof);
    }

    function test_RevertWhen_OtherProgramVKey() public withFixture {
        // Even an accepted vkey must be the one the proof was made for.
        bytes32 other = bytes32(uint256(vkey) ^ 1);
        registry.setVKey(other, true);
        vm.expectRevert();
        registry.verify(other, publicValues, proof);
    }

    function test_RevertWhen_ProofBitFlipped() public withFixture {
        bytes memory bad = bytes.concat(proof);
        bad[bad.length - 1] ^= 0x01;
        vm.expectRevert();
        registry.verify(vkey, publicValues, bad);
    }

    function test_ClaimGas() public withFixture {
        vm.prank(v.wallet);
        uint256 g = gasleft();
        registry.claim(vkey, publicValues, proof);
        emit log_named_uint("claim gas (incl. mock EAS)", g - gasleft());
    }
}
