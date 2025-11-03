// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import "./SystemV2.sol";
import "./extension/Protectable.sol";
import "./interface/0.8.x/IValidatorSet.sol";
import "./interface/0.8.x/IGovToken.sol";
import "./interface/0.8.x/IStakeCredit.sol";
import "./lib/0.8.x/Utils.sol";

pragma experimental ABIEncoderV2;

contract StakeHub is SystemV2, Initializable, Protectable {
    using Utils for string;
    using Utils for bytes;
    using EnumerableSet for EnumerableSet.AddressSet;

    /*----------------- constants -----------------*/
    uint256 private constant TENDERMINT_PUBKEY_LENGTH = 32;

    address public constant DEAD_ADDRESS = address(0xdEaD);

    uint256 public constant BREATHE_BLOCK_INTERVAL = 1 days;

    bytes public constant INIT_VALIDATORSET_BYTES =
    hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000002a3dfa31d8399b1c7d1f0a8d3ccc6ec04d3bb15e000000000000000000000000f279d46a9eb046f62d8e3e47e81d5af65a31ecfc00000000000000000000000000000000000000000000000000000002540be400000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000204252fdca22121f95624ef6ec17820941f39f4c760d0dc2d2893e4ef25105273c0000000000000000000000003be3890de72a292218e28b2fef9c472e32c7f309000000000000000000000000ae2a42970db03a628043f8e8b755485c9041edb600000000000000000000000000000000000000000000000000000002540be40000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020d1fee102c5c6a425a1056712154cbc077197bad5bad92507aba29ba36f920776000000000000000000000000e57c33d5bacc3e91156a6247092f920803efb8b7000000000000000000000000a616406e5f09809efa61f2be616429c05a934d0600000000000000000000000000000000000000000000000000000002540be40000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020f0ec25202200513318f455cb026eeedeb41d90cba9085635816cd73b4d85f10a";

    // receive fund status
    uint8 private constant _DISABLE = 0;
    uint8 private constant _ENABLE = 1;

    /*----------------- structs for initialization -----------------*/
    struct InitialValidator {
        address consensusAddress;
        address operatorAddress;
        uint64 votingPower;
        bytes tendermintPublicKey;
    }

    /*----------------- errors -----------------*/
    // @notice signature: 0x5f28f62b
    error ValidatorExisted();
    // @notice signature: 0x056e8811
    error ValidatorNotExisted();
    // @notice signature: 0x4b6b857d
    error ValidatorNotJailed();
    // @notice signature: 0x3cdeb0ea
    error DuplicateConsensusAddress();
    // @notice signature: 0xc0bf4143
    error DuplicateMoniker();
    // @notice signature: 0x2f64097e
    error SelfDelegationNotEnough();
    // @notice signature: 0x5dba5ad7
    error InvalidMoniker();
    // @notice signature: 0xca40c236
    error InvalidConsensusAddress();
    // @notice signature: 0x3f259b7a
    error UpdateTooFrequently();
    // @notice signature: 0x5c32dd9c
    error JailTimeNotExpired();
    // @notice signature: 0xdc6f0bdd
    error DelegationAmountTooSmall();
    // @notice signature: 0x64689203
    error OnlySelfDelegation();
    // @notice signature: 0x9811e0c7
    error ZeroShares();
    // @notice signature: 0xf0e3e629
    error SameValidator();
    // @notice signature: 0xbd52fcdb
    error NoMoreFelonyAllowed();
    // @notice signature: 0x37233762
    error AlreadySlashed();
    // @notice signature: 0x90b8ec18
    error TransferFailed();
    // @notice signature: 0x41abc801
    error InvalidRequest();
    // @notice signature: 0x539707fb
    error GenesisValidatorCannotDelegate();
    // @notice signature: 0xd5642d99
    error GenesisValidatorCannotUndelegate();
    error ConsensusAddressExpired();
    // @notice signature: 0x0d7b78d4
    error InvalidSynPackage();
    // @notice signature: 0x682a6e7c
    error InvalidValidator();
    // @notice signature: 0x2d4160cd
    error InvalidTendermintPubKey();

    /*----------------- storage -----------------*/
    uint8 private _receiveFundStatus;
    uint256 public transferGasLimit;

    // stake params
    uint256 public minSelfDelegationMETIS;
    uint256 public minDelegationMETISChange;
    uint256 public maxElectedValidators;
    uint256 public unbondPeriod;
    uint256 public epochLength;

    // slash params
    uint256 public downtimeSlashAmount;
    uint256 public felonySlashAmount;
    uint256 public downtimeJailTime;
    uint256 public felonyJailTime;

    // validator operator address set
    EnumerableSet.AddressSet private _validatorSet;
    // validator operator address => validator info
    mapping(address => Validator) private _validators;
    // validator moniker set(hash of the moniker)
    mapping(bytes32 => bool) private _monikerSet;
    // validator consensus address => validator operator address
    mapping(address => address) public consensusToOperator;
    // validator consensus address => expiry date
    mapping(address => uint256) public consensusExpiration;

    // total number of current jailed validators
    uint256 public numOfJailed;
    // max number of jailed validators between breathe block(only for malicious vote and double sign)
    uint256 public maxFelonyBetweenBreatheBlock;
    // index(timestamp / breatheBlockInterval) => number of malicious vote and double sign slash
    mapping(uint256 => uint256) private _felonyMap;
    // slash key => slash jail time
    mapping(bytes32 => uint256) private _felonyRecords;

    /*----------------- structs and events -----------------*/
    struct StakeMigrationPackage {
        address operatorAddress; // the operator address of the target validator to delegate to
        address delegator; // the beneficiary of the delegation
        address refundAddress; // the Beacon Chain address to refund the fund if migration failed
        uint256 amount; // the amount of METIS to be migrated(decimal: 18)
    }

    enum StakeMigrationRespCode {
        MIGRATE_SUCCESS,
        CLAIM_FUND_FAILED,
        VALIDATOR_NOT_EXISTED,
        VALIDATOR_JAILED,
        INVALID_DELEGATOR
    }

    struct Validator {
        address consensusAddress;
        address operatorAddress;
        address creditContract;
        uint256 createdTime;
        Description description;
        bool jailed;
        uint256 jailUntil;
        uint256 updateTime;
        bytes tendermintPubKey;
        uint256 votingPower;
        uint256[18] __reservedSlots;
    }

    struct Description {
        string moniker;
        string identity;
        string website;
        string details;
    }

    enum SlashType {
        DoubleSign,
        DownTime,
        MaliciousVote
    }

    event ValidatorCreated(
        address indexed consensusAddress,
        address indexed operatorAddress,
        address indexed creditContract
    );
    event StakeCreditInitialized(address indexed operatorAddress, address indexed creditContract);
    event ConsensusAddressEdited(address indexed operatorAddress, address indexed newConsensusAddress);
    event DescriptionEdited(address indexed operatorAddress);
    event Delegated(address indexed operatorAddress, address indexed delegator, uint256 shares, uint256 metisAmount);
    event Undelegated(address indexed operatorAddress, address indexed delegator, uint256 shares, uint256 metisAmount);
    event ValidatorSlashed(
        address indexed operatorAddress, uint256 jailUntil, uint256 slashAmount, SlashType slashType
    );
    event ValidatorJailed(address indexed operatorAddress);
    event ValidatorEmptyJailed(address indexed operatorAddress);
    event ValidatorUnjailed(address indexed operatorAddress);
    event Claimed(address indexed operatorAddress, address indexed delegator, uint256 metisAmount);

    /*----------------- modifiers -----------------*/
    modifier validatorExist(
        address operatorAddress
    ) {
        if (!_validatorSet.contains(operatorAddress)) revert ValidatorNotExisted();
        _;
    }

    modifier enableReceivingFund() {
        _receiveFundStatus = _ENABLE;
        _;
        _receiveFundStatus = _DISABLE;
    }

    receive() external payable {
        // to prevent METIS from being lost
        if (_receiveFundStatus != _ENABLE) revert();
    }

    /**
     * @dev this function is invoked by Metis Tendermint consensus engine during the hard fork
     */
    function initialize() external initializer {
        transferGasLimit = 5000;
        minSelfDelegationMETIS = 20_000 ether;
        minDelegationMETISChange = 1 ether;
        maxElectedValidators = 21;
        unbondPeriod = 7 days;
        epochLength = 1000;
        downtimeSlashAmount = 10 ether;
        felonySlashAmount = 200 ether;
        downtimeJailTime = 2 days;
        felonyJailTime = 30 days;
        maxFelonyBetweenBreatheBlock = 2;
        // Different address will be set depending on the environment
        __Protectable_init_unchained(0xA08BC19924B51B0BDAA8C5938DE31EDED75701F2);

        // Initialize validators from INIT_VALIDATORSET_BYTES
        _initializeValidatorsFromBytes();
    }

    /*----------------- external functions -----------------*/
    /**
     * @param consensusAddress the consensus address of the validator
     * @param tendermintPubKey the Tendermint/Malachite public key (32 bytes Ed25519)
     * @param description the description of the validator
     */
    function createValidator(
        address consensusAddress,
        bytes calldata tendermintPubKey,
        Description calldata description
    ) external payable whenNotPaused notInBlackList {
        // basic check
        address operatorAddress = msg.sender;
        if (_validatorSet.contains(operatorAddress)) revert ValidatorExisted();

        if (consensusToOperator[consensusAddress] != address(0)) {
            revert DuplicateConsensusAddress();
        }
        bytes32 monikerHash = keccak256(abi.encodePacked(description.moniker));
        if (_monikerSet[monikerHash]) revert DuplicateMoniker();

        uint256 delegation = msg.value; // All funds are used for delegation
        if (delegation < minSelfDelegationMETIS) revert SelfDelegationNotEnough();

        if (consensusAddress == address(0)) revert InvalidConsensusAddress();
        if (!_checkMoniker(description.moniker)) revert InvalidMoniker();

        if (tendermintPubKey.length != TENDERMINT_PUBKEY_LENGTH) revert InvalidTendermintPubKey();

        // deploy stake credit proxy contract
        address creditContract = _deployStakeCredit(operatorAddress, description.moniker);

        _validatorSet.add(operatorAddress);
        _monikerSet[monikerHash] = true;
        Validator storage valInfo = _validators[operatorAddress];
        valInfo.consensusAddress = consensusAddress;
        valInfo.operatorAddress = operatorAddress;
        valInfo.creditContract = creditContract;
        valInfo.createdTime = block.timestamp;
        valInfo.description = description;
        valInfo.updateTime = block.timestamp;
        valInfo.tendermintPubKey = tendermintPubKey;
//        valInfo.votingPower // come from IStakeCredit when get

        consensusToOperator[consensusAddress] = operatorAddress;

        emit ValidatorCreated(consensusAddress, operatorAddress, creditContract);
        emit Delegated(operatorAddress, operatorAddress, delegation, delegation);

        IGovToken(GOV_TOKEN_ADDR).sync(creditContract, operatorAddress);
    }

    /**
     * @param newConsensusAddress the new consensus address of the validator
     */
    function editConsensusAddress(
        address newConsensusAddress
    ) external whenNotPaused notInBlackList validatorExist(_bep410MsgSender()) {
        if (newConsensusAddress == address(0)) revert InvalidConsensusAddress();
        if (consensusToOperator[newConsensusAddress] != address(0)) {
            revert DuplicateConsensusAddress();
        }

        address operatorAddress = _bep410MsgSender();
        Validator storage valInfo = _validators[operatorAddress];
        if (valInfo.updateTime + BREATHE_BLOCK_INTERVAL > block.timestamp) revert UpdateTooFrequently();

        consensusExpiration[valInfo.consensusAddress] = block.timestamp;
        valInfo.consensusAddress = newConsensusAddress;
        valInfo.updateTime = block.timestamp;
        consensusToOperator[newConsensusAddress] = operatorAddress;

        emit ConsensusAddressEdited(operatorAddress, newConsensusAddress);
    }

    /**
     * @notice the moniker of the validator will be ignored as it is not editable
     * @param description the new description of the validator
     */
    function editDescription(
        Description memory description
    ) external whenNotPaused notInBlackList validatorExist(_bep410MsgSender()) {
        address operatorAddress = _bep410MsgSender();
        Validator storage valInfo = _validators[operatorAddress];
        if (valInfo.updateTime + BREATHE_BLOCK_INTERVAL > block.timestamp) revert UpdateTooFrequently();

        description.moniker = valInfo.description.moniker;
        valInfo.description = description;
        valInfo.updateTime = block.timestamp;

        emit DescriptionEdited(operatorAddress);
    }

    /**
     * @param operatorAddress the operator address of the validator to be unjailed
     */
    function unjail(
        address operatorAddress
    ) external whenNotPaused notInBlackList validatorExist(operatorAddress) {
        Validator storage valInfo = _validators[operatorAddress];
        if (!valInfo.jailed) revert ValidatorNotJailed();

        if (IStakeCredit(valInfo.creditContract).getPooledMETIS(operatorAddress) < minSelfDelegationMETIS) {
            revert SelfDelegationNotEnough();
        }
        if (valInfo.jailUntil > block.timestamp) revert JailTimeNotExpired();

        valInfo.jailed = false;
        numOfJailed -= 1;
        emit ValidatorUnjailed(operatorAddress);
    }

    /**
     * @param operatorAddress the operator address of the validator to be delegated to
     * @param delegateVotePower whether to delegate vote power to the validator
     */
    function delegate(
        address operatorAddress,
        bool delegateVotePower
    ) external payable whenNotPaused notInBlackList validatorExist(operatorAddress) {
        uint256 metisAmount = msg.value;
        if (metisAmount < minDelegationMETISChange) revert DelegationAmountTooSmall();

        address delegator = msg.sender;
        Validator memory valInfo = _validators[operatorAddress];

        // Only the validator itself can delegate to itself
        if (delegator != operatorAddress) revert OnlySelfDelegation();

        // Genesis validators (created via initialize) cannot delegate
        if (valInfo.creditContract == address(0)) revert GenesisValidatorCannotDelegate();

        uint256 shares = IStakeCredit(valInfo.creditContract).delegate{value: metisAmount}(delegator);
        emit Delegated(operatorAddress, delegator, shares, metisAmount);

        IGovToken(GOV_TOKEN_ADDR).sync(valInfo.creditContract, delegator);
        if (delegateVotePower) {
            IGovToken(GOV_TOKEN_ADDR).delegateVote(delegator, operatorAddress);
        }
    }

    /**
     * @dev Undelegate METIS from a validator, fund is only claimable few days later
     * @param operatorAddress the operator address of the validator to be undelegated from
     * @param shares the shares to be undelegated
     */
    function undelegate(
        address operatorAddress,
        uint256 shares
    ) external whenNotPaused notInBlackList validatorExist(operatorAddress) {
        if (shares == 0) revert ZeroShares();

        address delegator = msg.sender;
        Validator memory valInfo = _validators[operatorAddress];

        // Only the validator itself can undelegate from itself
        if (delegator != operatorAddress) revert OnlySelfDelegation();

        // Genesis validators (created via initialize) cannot undelegate
        if (valInfo.creditContract == address(0)) revert GenesisValidatorCannotUndelegate();

        uint256 metisAmount = IStakeCredit(valInfo.creditContract).undelegate(delegator, shares);
        emit Undelegated(operatorAddress, delegator, shares, metisAmount);

        _checkValidatorSelfDelegation(operatorAddress);

        IGovToken(GOV_TOKEN_ADDR).sync(valInfo.creditContract, delegator);
    }

    /**
     * @dev Claim the undelegated METIS from the pool after unbondPeriod
     * @param operatorAddress the operator address of the validator
     * @param requestNumber the request number of the undelegation. 0 means claim all
     */
    function claim(address operatorAddress, uint256 requestNumber) external whenNotPaused notInBlackList {
        _claim(operatorAddress, requestNumber);
    }

    /**
     * @dev Claim the undelegated METIS from the pools after unbondPeriod
     * @param operatorAddresses the operator addresses of the validator
     * @param requestNumbers numbers of the undelegation requests. 0 means claim all
     */
    function claimBatch(
        address[] calldata operatorAddresses,
        uint256[] calldata requestNumbers
    ) external whenNotPaused notInBlackList {
        if (operatorAddresses.length != requestNumbers.length) revert InvalidRequest();
        for (uint256 i; i < operatorAddresses.length; ++i) {
            _claim(operatorAddresses[i], requestNumbers[i]);
        }
    }

    /**
     * @dev Sync the gov tokens of validators in operatorAddresses
     * @param operatorAddresses the operator addresses of the validators
     * @param account the account to sync gov tokens to
     */
    function syncGovToken(
        address[] calldata operatorAddresses,
        address account
    ) external whenNotPaused notInBlackList {
        uint256 _length = operatorAddresses.length;
        address[] memory stakeCredits = new address[](_length);
        address credit;
        for (uint256 i = 0; i < _length; ++i) {
            if (!_validatorSet.contains(operatorAddresses[i])) revert ValidatorNotExisted();
            credit = _validators[operatorAddresses[i]].creditContract;
            stakeCredits[i] = credit;
        }

        IGovToken(GOV_TOKEN_ADDR).syncBatch(stakeCredits, account);
    }

    /*----------------- system functions -----------------*/
    /**
     * @dev Downtime slash. Only the `SlashIndicator` contract can call this function.
     */
    function downtimeSlash(
        address consensusAddress
    ) external onlySlash {
        address operatorAddress = consensusToOperator[consensusAddress];
        if (!_validatorSet.contains(operatorAddress)) revert ValidatorNotExisted(); // should never happen
        Validator storage valInfo = _validators[operatorAddress];

        // slash
        uint256 slashAmount = IStakeCredit(valInfo.creditContract).slash(downtimeSlashAmount);
        uint256 jailUntil = block.timestamp + downtimeJailTime;
        _jailValidator(valInfo, jailUntil);

        emit ValidatorSlashed(operatorAddress, jailUntil, slashAmount, SlashType.DownTime);

        IGovToken(GOV_TOKEN_ADDR).sync(valInfo.creditContract, operatorAddress);
    }

    /**
     * @dev Double sign slash. Only the `SlashIndicator` contract can call this function.
     */
    function doubleSignSlash(
        address consensusAddress
    ) external onlySlash whenNotPaused {
        address operatorAddress = consensusToOperator[consensusAddress];
        if (!_validatorSet.contains(operatorAddress)) revert ValidatorNotExisted(); // should never happen
        Validator storage valInfo = _validators[operatorAddress];

        uint256 index = block.timestamp / BREATHE_BLOCK_INTERVAL;
        // This is to prevent many honest validators being slashed at the same time because of implementation bugs
        if (_felonyMap[index] >= maxFelonyBetweenBreatheBlock) revert NoMoreFelonyAllowed();
        _felonyMap[index] += 1;

        // check if the consensusAddress has already expired
        if (
            consensusExpiration[consensusAddress] != 0
            && consensusExpiration[consensusAddress] + BREATHE_BLOCK_INTERVAL < block.timestamp
        ) {
            revert ConsensusAddressExpired();
        }

        // slash
        (bool canSlash, uint256 jailUntil) = _checkFelonyRecord(operatorAddress, SlashType.DoubleSign);
        if (!canSlash) revert AlreadySlashed();
        uint256 slashAmount = IStakeCredit(valInfo.creditContract).slash(felonySlashAmount);
        _jailValidator(valInfo, jailUntil);

        emit ValidatorSlashed(operatorAddress, jailUntil, slashAmount, SlashType.DoubleSign);

        IGovToken(GOV_TOKEN_ADDR).sync(valInfo.creditContract, operatorAddress);
    }

    /**
     * @param key the key of the param
     * @param value the value of the param
     */
    function updateParam(string calldata key, bytes calldata value) external onlyGov {
        if (key.compareStrings("transferGasLimit")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newTransferGasLimit = value.bytesToUint256(32);
            if (newTransferGasLimit < 2300 || newTransferGasLimit > 10_000) revert InvalidValue(key, value);
            transferGasLimit = newTransferGasLimit;
        } else if (key.compareStrings("minSelfDelegationMETIS")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newMinSelfDelegationMETIS = value.bytesToUint256(32);
            if (newMinSelfDelegationMETIS < 1000 ether || newMinSelfDelegationMETIS > 100_000 ether) {
                revert InvalidValue(key, value);
            }
            minSelfDelegationMETIS = newMinSelfDelegationMETIS;
        } else if (key.compareStrings("minDelegationMETISChange")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newMinDelegationMETISChange = value.bytesToUint256(32);
            if (newMinDelegationMETISChange < 0.1 ether || newMinDelegationMETISChange > 10 ether) {
                revert InvalidValue(key, value);
            }
            minDelegationMETISChange = newMinDelegationMETISChange;
        } else if (key.compareStrings("maxElectedValidators")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newMaxElectedValidators = value.bytesToUint256(32);
            if (newMaxElectedValidators == 0 || newMaxElectedValidators > 500) revert InvalidValue(key, value);
            maxElectedValidators = newMaxElectedValidators;
        } else if (key.compareStrings("unbondPeriod")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newUnbondPeriod = value.bytesToUint256(32);
            if (newUnbondPeriod < 3 days || newUnbondPeriod > 30 days) revert InvalidValue(key, value);
            unbondPeriod = newUnbondPeriod;
        } else if (key.compareStrings("downtimeSlashAmount")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newDowntimeSlashAmount = value.bytesToUint256(32);
            if (newDowntimeSlashAmount < 1 ether || newDowntimeSlashAmount >= felonySlashAmount) {
                revert InvalidValue(key, value);
            }
            downtimeSlashAmount = newDowntimeSlashAmount;
        } else if (key.compareStrings("felonySlashAmount")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newFelonySlashAmount = value.bytesToUint256(32);
            if (newFelonySlashAmount < 10 ether || newFelonySlashAmount <= downtimeSlashAmount) {
                revert InvalidValue(key, value);
            }
            felonySlashAmount = newFelonySlashAmount;
        } else if (key.compareStrings("downtimeJailTime")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newDowntimeJailTime = value.bytesToUint256(32);
            if (newDowntimeJailTime < 1 days || newDowntimeJailTime >= felonyJailTime) revert InvalidValue(key, value);
            downtimeJailTime = newDowntimeJailTime;
        } else if (key.compareStrings("felonyJailTime")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newFelonyJailTime = value.bytesToUint256(32);
            if (newFelonyJailTime < 3 days || newFelonyJailTime <= downtimeJailTime) revert InvalidValue(key, value);
            felonyJailTime = newFelonyJailTime;
        } else if (key.compareStrings("maxFelonyBetweenBreatheBlock")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newJailedPerDay = value.bytesToUint256(32);
            if (newJailedPerDay == 0) revert InvalidValue(key, value);
            maxFelonyBetweenBreatheBlock = newJailedPerDay;
        } else if (key.compareStrings("stakeHubProtector")) {
            if (value.length != 20) revert InvalidValue(key, value);
            address newStakeHubProtector = value.bytesToAddress(20);
            if (newStakeHubProtector == address(0)) revert InvalidValue(key, value);
            _setProtector(newStakeHubProtector);
        } else if (key.compareStrings("epochLength")) {
            if (value.length != 32) revert InvalidValue(key, value);
            uint256 newEpochLength = value.bytesToUint256(32);
            if (newEpochLength == 0 || newEpochLength > 100000) revert InvalidValue(key, value);
            epochLength = newEpochLength;
        } else {
            revert UnknownParam(key, value);
        }
        emit ParamChange(key, value);
    }

    /*----------------- view functions -----------------*/
    /**
     * @param operatorAddress the operator address of the validator
     * @param index the index of the day to query(timestamp / 1 days)
     *
     * @return the validator's reward of the day
     */
    function getValidatorRewardRecord(address operatorAddress, uint256 index) external view returns (uint256) {
        if (!_validatorSet.contains(operatorAddress)) revert ValidatorNotExisted();
        return IStakeCredit(_validators[operatorAddress].creditContract).rewardRecord(index);
    }

    /**
     * @param operatorAddress the operator address of the validator
     * @param index the index of the day to query(timestamp / 1 days)
     *
     * @return the validator's total pooled METIS of the day
     */
    function getValidatorTotalPooledMETISRecord(address operatorAddress, uint256 index) external view returns (uint256) {
        if (!_validatorSet.contains(operatorAddress)) revert ValidatorNotExisted();
        return IStakeCredit(_validators[operatorAddress].creditContract).totalPooledMETISRecord(index);
    }

    /**
     * @notice pagination query all validators' operator address and credit contract address
     *
     * @param offset the offset of the query
     * @param limit the limit of the query
     *
     * @return operatorAddrs operator addresses
     * @return creditAddrs credit contract addresses
     * @return totalLength total number of validators
     */
    function getValidators(
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory operatorAddrs, address[] memory creditAddrs, uint256 totalLength) {
        totalLength = _validatorSet.length();
        if (offset >= totalLength) {
            return (operatorAddrs, creditAddrs, totalLength);
        }

        limit = limit == 0 ? totalLength : limit;
        uint256 count = (totalLength - offset) > limit ? limit : (totalLength - offset);
        operatorAddrs = new address[](count);
        creditAddrs = new address[](count);
        for (uint256 i; i < count; ++i) {
            operatorAddrs[i] = _validatorSet.at(offset + i);
            creditAddrs[i] = _validators[operatorAddrs[i]].creditContract;
        }
    }

    /**
     * @notice get the consensus address of a validator
     *
     * @param operatorAddress the operator address of the validator
     *
     * @return consensusAddress the consensus address of the validator
     */
    function getValidatorConsensusAddress(
        address operatorAddress
    ) external view returns (address consensusAddress) {
        Validator memory valInfo = _validators[operatorAddress];
        consensusAddress = valInfo.consensusAddress;
    }

    /**
     * @notice get the credit contract address of a validator
     *
     * @param operatorAddress the operator address of the validator
     *
     * @return creditContract the credit contract address of the validator
     */
    function getValidatorCreditContract(
        address operatorAddress
    ) external view returns (address creditContract) {
        Validator memory valInfo = _validators[operatorAddress];
        creditContract = valInfo.creditContract;
    }

    /**
     * @notice get the basic info of a validator
     *
     * @param operatorAddress the operator address of the validator
     *
     * @return createdTime the creation time of the validator
     * @return jailed whether the validator is jailed
     * @return jailUntil the jail time of the validator
     */
    function getValidatorBasicInfo(
        address operatorAddress
    ) external view returns (uint256 createdTime, bool jailed, uint256 jailUntil) {
        Validator memory valInfo = _validators[operatorAddress];
        createdTime = valInfo.createdTime;
        jailed = valInfo.jailed;
        jailUntil = valInfo.jailUntil;
    }

    /**
     * @param operatorAddress the operator address of the validator
     *
     * @return the description of a validator
     */
    function getValidatorDescription(
        address operatorAddress
    ) external view validatorExist(operatorAddress) returns (Description memory) {
        return _validators[operatorAddress].description;
    }

    /**
     * @param operatorAddress the operator address of the validator
     *
     * @return the updateTime of a validator
     */
    function getValidatorUpdateTime(
        address operatorAddress
    ) external view validatorExist(operatorAddress) returns (uint256) {
        return _validators[operatorAddress].updateTime;
    }

    /**
     * @dev this function will be used by Parlia consensus engine.
     *
     * @notice get the election info of a validator
     *
     * @param offset the offset of the query
     * @param limit the limit of the query
     *
     * @return consensusAddrs the consensus addresses of the validators
     * @return votingPowers the voting powers of the validators. The voting power will be 0 if the validator is jailed.
     * @return operatorAddrs the operator addresses of the validators
     * @return tendermintPubKeys the Tendermint/Malachite public keys of the validators (32 bytes Ed25519)
     * @return totalLength the total number of validators
     */
    function getValidatorElectionInfo(
        uint256 offset,
        uint256 limit
    )
    external
    view
    returns (
        address[] memory consensusAddrs,
        uint256[] memory votingPowers,
        address[] memory operatorAddrs,
        bytes[] memory tendermintPubKeys,
        uint256 totalLength
    )
    {
        totalLength = _validatorSet.length();
        if (offset >= totalLength) {
            return (consensusAddrs, votingPowers, operatorAddrs, tendermintPubKeys, totalLength);
        }

        limit = limit == 0 ? totalLength : limit;
        uint256 count = (totalLength - offset) > limit ? limit : (totalLength - offset);
        consensusAddrs = new address[](count);
        votingPowers = new uint256[](count);
        operatorAddrs = new address[](count);
        tendermintPubKeys = new bytes[](count);
        for (uint256 i; i < count; ++i) {
            address operatorAddress = _validatorSet.at(offset + i);
            Validator memory valInfo = _validators[operatorAddress];
            consensusAddrs[i] = valInfo.consensusAddress;

            // Dynamic voting power calculation
            if (valInfo.jailed) {
                votingPowers[i] = 0;
            } else if (valInfo.creditContract == address(0)) {
                // Use stored votingPower for validators without credit contract (initial validators)
                votingPowers[i] = valInfo.votingPower;
            } else {
                // Use total pooled METIS for validators with credit contract
                votingPowers[i] = IStakeCredit(valInfo.creditContract).totalPooledMETIS();
            }

            operatorAddrs[i] = valInfo.operatorAddress;
            tendermintPubKeys[i] = valInfo.tendermintPubKey;
        }
    }

    /**
     * @dev Get the INIT_VALIDATORSET_BYTES constant for debugging
     * @return The INIT_VALIDATORSET_BYTES constant value
     */
    function getInitValidatorSetBytes()
    external
    pure
    returns (bytes memory)
    {
        return INIT_VALIDATORSET_BYTES;
    }

    /*----------------- internal functions -----------------*/
    function _checkMoniker(
        string memory moniker
    ) internal pure returns (bool) {
        bytes memory bz = bytes(moniker);

        // 1. moniker length should be between 3 and 9
        if (bz.length < 3 || bz.length > 9) {
            return false;
        }

        // 2. first character should be uppercase
        if (uint8(bz[0]) < 65 || uint8(bz[0]) > 90) {
            return false;
        }

        // 3. only alphanumeric characters are allowed
        for (uint256 i = 1; i < bz.length; ++i) {
            // Check if the ASCII value of the character falls outside the range of alphanumeric characters
            if (
                (uint8(bz[i]) < 48 || uint8(bz[i]) > 57) && (uint8(bz[i]) < 65 || uint8(bz[i]) > 90)
                && (uint8(bz[i]) < 97 || uint8(bz[i]) > 122)
            ) {
                // Character is a special character
                return false;
            }
        }

        // No special characters found
        return true;
    }

    function _deployStakeCredit(address operatorAddress, string memory moniker) internal returns (address) {
        address creditProxy = address(new TransparentUpgradeableProxy(STAKE_CREDIT_ADDR, DEAD_ADDRESS, ""));
        IStakeCredit(creditProxy).initialize{value: msg.value}(operatorAddress, moniker);
        emit StakeCreditInitialized(operatorAddress, creditProxy);

        return creditProxy;
    }

    function _checkValidatorSelfDelegation(
        address operatorAddress
    ) internal {
        Validator storage valInfo = _validators[operatorAddress];
        if (valInfo.jailed) {
            return;
        }
        if (IStakeCredit(valInfo.creditContract).getPooledMETIS(operatorAddress) < minSelfDelegationMETIS) {
            _jailValidator(valInfo, block.timestamp + downtimeJailTime);
            IValidatorSet(VALIDATOR_CONTRACT_ADDR).felony(valInfo.consensusAddress);
        }
    }

    function _checkFelonyRecord(address operatorAddress, SlashType slashType) internal returns (bool, uint256) {
        bytes32 slashKey = keccak256(abi.encodePacked(operatorAddress, slashType));
        uint256 jailUntil = _felonyRecords[slashKey];
        // for double sign and malicious vote slash
        // if the validator is already jailed, no need to slash again
        if (jailUntil > block.timestamp) {
            return (false, 0);
        }
        jailUntil = block.timestamp + felonyJailTime;
        _felonyRecords[slashKey] = jailUntil;
        return (true, jailUntil);
    }

    function _jailValidator(Validator storage valInfo, uint256 jailUntil) internal {
        // keep the last eligible validator
        bool isLast = (numOfJailed >= _validatorSet.length() - 1);
        if (isLast) {
            // If staking channel is closed, then BC-fusion is finished and we should keep the last eligible validator here
            emit ValidatorEmptyJailed(valInfo.operatorAddress);
            return;
        }

        if (jailUntil > valInfo.jailUntil) {
            valInfo.jailUntil = jailUntil;
        }

        if (!valInfo.jailed) {
            valInfo.jailed = true;
            numOfJailed += 1;

            emit ValidatorJailed(valInfo.operatorAddress);
        }
    }

    function _claim(address operatorAddress, uint256 requestNumber) internal validatorExist(operatorAddress) {
        uint256 metisAmount = IStakeCredit(_validators[operatorAddress].creditContract).claim(msg.sender, requestNumber);
        emit Claimed(operatorAddress, msg.sender, metisAmount);
    }

    function _bep410MsgSender() internal view returns (address) {
        return msg.sender;
    }

    function _bep563MsgSender() internal view returns (address) {
        if (consensusToOperator[msg.sender] != address(0)) {
            return consensusToOperator[msg.sender];
        }

        return _bep410MsgSender();
    }

    /**
     * @dev Initialize validators from INIT_VALIDATORSET_BYTES
     * This function is called during contract initialization to set up initial validators
     */
    function _initializeValidatorsFromBytes() internal {
        InitialValidator[] memory validatorSet = abi.decode(INIT_VALIDATORSET_BYTES, (InitialValidator[]));

        for (uint256 i; i < validatorSet.length; ++i) {
            InitialValidator memory val = validatorSet[i];

            address operatorAddress = val.operatorAddress;

            // Add to _validatorSet
            _validatorSet.add(operatorAddress);

            // Create validator info using storage reference
            Validator storage valInfo = _validators[operatorAddress];
            valInfo.consensusAddress = val.consensusAddress;
            valInfo.operatorAddress = operatorAddress;
            valInfo.creditContract = address(0);// the genesis val not have creditContract
            valInfo.createdTime = block.timestamp;
            valInfo.description = Description({
                moniker: "",
                identity: "",
                website: "",
                details: ""
            });
            valInfo.jailed = false;
            valInfo.jailUntil = 0;
            valInfo.updateTime = block.timestamp;
            valInfo.tendermintPubKey = val.tendermintPublicKey;
            valInfo.votingPower = uint256(val.votingPower) * 1e10;

            // Set up mappings
            consensusToOperator[val.consensusAddress] = operatorAddress;
        }
    }
}
