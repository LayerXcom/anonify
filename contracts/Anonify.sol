pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./ReportHandle.sol";
import "./utils/Secp256k1.sol";

// Consider: Avoid inheritting
contract Anonify is ReportHandle {
    address private _owner;
    uint256 private _mrenclaveVer;

    event StoreCiphertext(bytes ciphertext);
    event StoreHandshake(bytes handshake);

    constructor(
        bytes memory _report,
        bytes memory _reportSig,
        bytes memory _handshake,
        uint256 mrenclaveVer
    ) ReportHandle(_report, _reportSig) public {
        _owner = msg.sender;
        _mrenclaveVer = mrenclaveVer;
        handshake(_handshake);
     }

    modifier onlyOwner() {
        require(_owner == msg.sender, "caller is not the owner");
        _;
    }

    // a new TEE participant joins the group.
    function joinGroup(
        bytes memory _report,
        bytes memory _reportSig,
        bytes memory _handshake
    ) public {
        handleReport(_report, _reportSig);
        handshake(_handshake);
    }

    function updateMrEnclave(
        bytes memory _report,
        bytes memory _reportSig
    ) public onlyOwner {
        updateMrEnclaveInner(_report, _reportSig);
    }

    // Store ciphertexts which is generated by trusted environment.
    function storeInstruction(
        bytes memory _newCiphertext,
        bytes memory _enclaveSig,
        bytes32 _msg
    ) public {
        address verifyingKey = Secp256k1.recover(_msg, _enclaveSig);
        require(verifyingKeyMapping[verifyingKey] == verifyingKey, "Invalid enclave signature.");

        emit StoreCiphertext(_newCiphertext);
    }

    function handshake(bytes memory _handshake) public {
        emit StoreHandshake(_handshake);
    }
}
