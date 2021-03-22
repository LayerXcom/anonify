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

    struct GroupKeyCounter {
        uint32 generation;
        uint32 epoch;
    }

    address private _owner;
    // A version of enclave binary
    uint32 private _mrenclaveVer;
    // Counter for enforcing the order of state transitions
    uint256 private _stateCounter;
    // Counter for enforcing the order of state transitions
    mapping(uint32 => GroupKeyCounter) private _groupKeyCounter;

    event StoreTreeKemCiphertext(bytes ciphertext, uint256 stateCounter);
    event StoreTreeKemHandshake(bytes handshake, uint256 stateCounter);
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
        bytes memory _handshake,
        uint32 _version,
        uint32 _rosterIdx
    ) public {
        require(_mrenclaveVer == _version, "Must be same version");

        handleReport(_report, _reportSig);
        // It is assumed that the nodes participate in the order of roster index,
        // and all the nodes finish participating before the state transition.
        _groupKeyCounter[_rosterIdx] = GroupKeyCounter(0, _rosterIdx + 1);
        storeTreeKemHandshake(_handshake);
    }

    // a recovered TEE node registers the report
    function registerReport(
        bytes memory _report,
        bytes memory _reportSig,
        uint32 _version,
        uint32 _rosterIdx
    ) public {
        require(_mrenclaveVer == _version, "Must be same version");

        handleReport(_report, _reportSig);
    }

    function updateMrenclave(
        bytes memory _report,
        bytes memory _reportSig,
        bytes memory _handshake,
        uint32 _newVersion,
        uint32 _rosterIdx
    ) public onlyOwner {
        require(_mrenclaveVer != _newVersion, "Must be new version");
        require(_rosterIdx == 0, "Only owner can update mrenclave");

        updateMrenclaveInner(_report, _reportSig);
        _mrenclaveVer = _newVersion;
        storeTreeKemHandshake(_handshake);
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
                sha256(
                    abi.encodePacked(
                        _newCiphertext,
                        _rosterIdx,
                        _generation,
                        _epoch
                    )
                ),
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
        require(
            _generation > _groupKeyCounter[_rosterIdx].generation,
            "generation must be bigger than the counter"
        );
        require(
            _epoch == _groupKeyCounter[_rosterIdx].epoch,
            "epoch must be equal with the counter"
        );

        uint256 incremented_state_counter = _stateCounter.add(1);

        _groupKeyCounter[_rosterIdx] = GroupKeyCounter(_generation, _epoch);
        _stateCounter = incremented_state_counter;
        emit StoreTreeKemCiphertext(_newCiphertext, incremented_state_counter);
    }

    function handshake(
        bytes memory _handshake,
        bytes memory _enclaveSig,
        uint32 _rosterIdx,
        uint32 _generation,
        uint32 _epoch
    ) public {
        address verifyingKey =
            Secp256k1.recover(
                sha256(
                    abi.encodePacked(
                        _handshake,
                        _rosterIdx,
                        _generation,
                        _epoch
                    )
                ),
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
        require(_generation == 0, "generation must be zero");
        require(
            _epoch > _groupKeyCounter[_rosterIdx].epoch,
            "epoch must be bigger than the counter"
        );

        _groupKeyCounter[_rosterIdx] = GroupKeyCounter(_generation, _epoch);
        storeTreeKemHandshake(_handshake);
    }

    function storeTreeKemHandshake(bytes memory _handshake) private {
        uint256 incremented_state_counter = _stateCounter.add(1);
        _stateCounter = incremented_state_counter;
        emit StoreTreeKemHandshake(_handshake, incremented_state_counter);
    }
}
