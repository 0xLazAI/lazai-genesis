pragma solidity 0.6.4;
pragma experimental ABIEncoderV2;

interface IStakeHub {
    function downtimeSlash(address validator) external;
    function maliciousVoteSlash(bytes calldata voteAddress) external;
    function doubleSignSlash(address validator) external;
    function voteToOperator(bytes calldata voteAddress) external view returns (address);
    function consensusToOperator(address validator) external view returns (address);
    function getValidatorConsensusAddress(address validator) external view returns (address);
    function getValidatorCreditContract(address validator) external view returns (address);
    function getValidatorVoteAddress(address validator) external view returns (bytes memory);
    function maxElectedValidators() external view returns (uint256);
    function distributeReward(address validator) external payable;
    
    // Malaketh-Layered: Add getValidatorElectionInfo for validator set updates
    function getValidatorElectionInfo(uint256 offset, uint256 limit) external view returns (
        address[] memory consensusAddrs,
        uint256[] memory votingPowers,
        bytes[] memory voteAddrs,
        bytes[] memory tendermintPubKeys,
        uint256 totalLength
    );
}
