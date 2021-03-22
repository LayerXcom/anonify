// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.4;
pragma experimental ABIEncoderV2;

import "./utils/SafeMath.sol";
import "./ReportHandle.sol";
import "./utils/Secp256k1.sol";
import "./utils/BytesUtils.sol";

// Consider: Avoid inheritting
contract Anonify is ReportHandle {
    using BytesUtils for bytes;
    using SafeMath for uint256;

    address private _owner;
    // A version of enclave binary
    uint32 private _mrenclaveVer;
    // Counter for enforcing the order of state transitions
    uint256 private _stateCounter;

    event JoinGroup(uint32 rosterIdx, bytes32 enclaveEncryptionKey);
    event StoreCiphertext(bytes ciphertext, uint256 stateCounter);
    event UpdateMrenclaveVer(uint32 newVersion);

    constructor() {
        _owner = msg.sender;
    }

    modifier onlyOwner() {
        require(_owner == msg.sender, "caller is not the owner");
        _;
    }

    // a new TEE node joins the group.
    function joinGroup(
        bytes memory _report,
        bytes memory _reportSig,
        uint32 _version,
        uint32 _rosterIdx
    ) public {
        require(_mrenclaveVer == _version, "Must be same version");

        bytes32 enclaveEncryptionKey = handleReport(_report, _reportSig);

        emit JoinGroup(_rosterIdx, enclaveEncryptionKey);
    }

    function updateMrenclave(
        bytes memory _report,
        bytes memory _reportSig,
        uint32 _newVersion,
        uint32 _rosterIdx
    ) public onlyOwner {
        require(_mrenclaveVer != _newVersion, "Must be new version");
        require(_rosterIdx == 0, "Only owner can update mrenclave");

        updateMrenclaveInner(_report, _reportSig);
        _mrenclaveVer = _newVersion;
        emit UpdateMrenclaveVer(_newVersion);
    }

    // Store ciphertexts which is generated by trusted environment.
    function storeCommand(
        bytes memory _newCiphertext,
        bytes memory _enclaveSig,
        uint32 _rosterIdx,
        uint32 _generation,
        uint32 _epoch
    ) public {
        address verifyingKey =
            Secp256k1.recover(
                sha256(abi.encodePacked(_newCiphertext, _rosterIdx, _generation, _epoch)),
                _enclaveSig
            );
        require(
            verifyingKey != address(0),
            "recovered verifyingKey was address(0)"
        );
        require(
            verifyingKeyMapping[verifyingKey] == verifyingKey,
            "Invalid enclave signature."
        );

        uint256 incremented_state_counter = _stateCounter.add(1);

        _stateCounter = incremented_state_counter;
        emit StoreCiphertext(_newCiphertext, incremented_state_counter);
    }
}
