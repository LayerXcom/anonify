pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./ReportHandle.sol";
import "./utils/Secp256k1.sol";
import "./utils/BytesUtils.sol";

// Consider: Avoid inheritting
contract Anonify is ReportHandle {
    address private _owner;
    uint32 private _mrenclaveVer;

    // An counter of registered roster index
    uint32 private _rosterIdxCounter;
    // Counter for enforcing the order of state transitions
    uint256 private _stateCounter;
    // Mapping of a sender and roster index
    mapping(address => uint32) private _senderToRosterIdx;

    event StoreCiphertext(
        bytes indexed ciphertext,
        uint256 indexed stateCounter
    );
    event StoreHandshake(bytes indexed handshake, uint256 indexed stateCounter);
    event UpdateMrenclaveVer(uint32 newVersion);

    constructor(
        bytes memory _report,
        bytes memory _reportSig,
        bytes memory _handshake,
        uint32 mrenclaveVer
    ) public ReportHandle(_report, _reportSig) {
        // The offset of roster index is 4.
        uint32 rosterIdx = BytesUtils.toUint32(_handshake, 4);
        require(rosterIdx == 0, "First roster_idx must be zero");

        _owner = msg.sender;
        _mrenclaveVer = mrenclaveVer;
        _senderToRosterIdx[msg.sender] = rosterIdx;
        _rosterIdxCounter = rosterIdx;
        storeHandshake(_handshake);
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
        require(
            _rosterIdx == _rosterIdxCounter + 1,
            "Joining the group must be ordered accordingly by roster index"
        );
        require(
            _senderToRosterIdx[msg.sender] == 0,
            "The msg.sender can join only once"
        );

        handleReport(_report, _reportSig);
        _senderToRosterIdx[msg.sender] = _rosterIdx;
        _rosterIdxCounter = _rosterIdx;
        storeHandshake(_handshake);
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
        _senderToRosterIdx[msg.sender] = _rosterIdx;
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
        storeHandshake(_handshake);
        emit UpdateMrenclaveVer(_newVersion);
    }

    // Store ciphertexts which is generated by trusted environment.
    function storeCommand(bytes memory _newCiphertext, bytes memory _enclaveSig)
        public
    {
        address verifyingKey =
            Secp256k1.recover(sha256(_newCiphertext), _enclaveSig);
        require(
            verifyingKey != address(0),
            "recovered verifyingKey was address(0)"
        );
        require(
            verifyingKeyMapping[verifyingKey] == verifyingKey,
            "Invalid enclave signature."
        );

        _stateCounter.add(1);
        emit StoreCiphertext(_newCiphertext, _stateCounter);
    }

    function handshake(
        bytes memory _handshake,
        bytes memory _enclaveSig,
        uint32 _rosterIdx
    ) public {
        require(
            _senderToRosterIdx[msg.sender] == _rosterIdx,
            "The roster index must be same as the registered one"
        );
        address verifyingKey =
            Secp256k1.recover(
                sha256(abi.encodePacked(_handshake, _rosterIdx)),
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

        storeHandshake(_handshake);
    }

    function storeHandshake(bytes memory _handshake) private {
        _stateCounter.add(1);
        emit StoreHandshake(_handshake, _stateCounter);
    }
}
