const {ethers} = require("ethers");

// Configure
const EPOCH_LENGTH = 1000;
const validators = [
    {
        consensusAddress: '0x0754445aeda0441230d3ab099b0942181915186c',
        operatorAddress: '0x3Ef11d03353cC6e5f342e7c4eFF81f43abe183f5',
        votingPower: 10000000000,
        tendermintPublicKey: '0x97007a7ab3b4ca24f8b88e6dceb764fe8bff810bf45fc16ef7bf0941fcbd7a27',
    },
    {
        consensusAddress: '0x3f8f2908b1b5b6ef3eec1968fcdf8340a6bec221',
        operatorAddress: '0x15cA00B3bd38ec4b065eb7463D4Ed8Ad3Ce9dBf6',
        votingPower: 10000000000,
        tendermintPublicKey: '0xdac4b2f85de5e04c301a077b08256f659dddf36a39578361b1999df56237ab8e',
    },
    {
        consensusAddress: '0x9ab1a8b89460fccd8eb6739352300988915c71fe',
        operatorAddress: '0x1f2d033A533Dc14c0c75D02FE6aDbC0AD4755107',
        votingPower: 10000000000,
        tendermintPublicKey: '0x1b494a5bc634bfa140c1f5b8f765c7c0203a5d3a73883542ec3dd0daafc36157',
    },
];

const pre_mainnet_validators = [
    {
        consensusAddress: '0xe679868786ae622d5837c54103617b3e82d40eb1',
        operatorAddress: '0xcba4b40b9956a0ecff90f98de264c0fab70b0929',
        votingPower: 10000000000,
        tendermintPublicKey: '0xe3f336ae0f78764c7575b25b17a3be74a3d37a21e5867ba705698f16993c269c',
    },
    {
        consensusAddress: '0x7ea234204bf328d830493b87f2978889f965327b',
        operatorAddress: '0x61af740ac2380114e8dcd4a3665384d7f14b1da2',
        votingPower: 10000000000,
        tendermintPublicKey: '0x08e1c850d14cc9a1ee73f87173af61324c2892377f6fbe5c334c35a582e2baa3',
    },
    {
        consensusAddress: '0x3fb2ed55f9fd3466a1ddefc96c6223e9c9cd401a',
        operatorAddress: '0x04f8335abbfad2c534ce324cb4e09e3925d29fd4',
        votingPower: 10000000000,
        tendermintPublicKey: '0x0836d78e877b362202e297216c76feae6e414d6ea0291f81cb445a6341b25b2b',
    },
];

const mainnet_validators = [
    {
        consensusAddress: '0x2a3dfa31d8399b1c7d1f0a8d3ccc6ec04d3bb15e',
        operatorAddress: '0xf279d46a9eb046f62d8e3e47e81d5af65a31ecfc',
        votingPower: 10000000000,
        tendermintPublicKey: '0x4252fdca22121f95624ef6ec17820941f39f4c760d0dc2d2893e4ef25105273c',
    },
    {
        consensusAddress: '0x3be3890de72a292218e28b2fef9c472e32c7f309',
        operatorAddress: '0xae2a42970db03a628043f8e8b755485c9041edb6',
        votingPower: 10000000000,
        tendermintPublicKey: '0xd1fee102c5c6a425a1056712154cbc077197bad5bad92507aba29ba36f920776',
    },
    {
        consensusAddress: '0xe57c33d5bacc3e91156a6247092f920803efb8b7',
        operatorAddress: '0xa616406e5f09809efa61f2be616429c05a934d06',
        votingPower: 10000000000,
        tendermintPublicKey: '0xf0ec25202200513318f455cb026eeedeb41d90cba9085635816cd73b4d85f10a',
    },
];

function generateExtraData(validators) {
    let extraVanity = Buffer.alloc(32);
    let validatorsBytes = extraDataSerialize(validators);
    let extraSeal = Buffer.alloc(65);
    return Buffer.concat([extraVanity, validatorsBytes, extraSeal]);
}

function extraDataSerialize(validators) {
    let n = validators.length;
    let arr = [];
    for (let i = 0; i < n; i++) {
        let validator = validators[i];

        let validatorData = Buffer.alloc(0);

        // 1. consensusAddress (20bytes)
        validatorData = Buffer.concat([
            validatorData,
            Buffer.from(validator.consensusAddress.slice(2), 'hex')
        ]);

        // 2. operatorAddress (20bytes)
        validatorData = Buffer.concat([
            validatorData,
            Buffer.from(validator.operatorAddress.slice(2), 'hex')
        ]);

        // 3. votingPower (8bytes，uint64)
        let votingPowerBuffer = Buffer.alloc(8);
        votingPowerBuffer.writeBigUInt64BE(BigInt(validator.votingPower), 0);
        validatorData = Buffer.concat([validatorData, votingPowerBuffer]);

        // 4. tendermintPublicKey (32bytes)
        validatorData = Buffer.concat([
            validatorData,
            Buffer.from(validator.tendermintPublicKey.slice(2), 'hex')
        ]);

        arr.push(validatorData);
    }

    // 5. epoch_length (8bytes，uint64)
    let epochLengthBuffer = Buffer.alloc(8);
    epochLengthBuffer.writeBigUInt64BE(BigInt(EPOCH_LENGTH), 0);
    arr.push(epochLengthBuffer);

    return Buffer.concat(arr);
}

extraValidatorBytes = generateExtraData(mainnet_validators);
validatorSetBytes = ethers.AbiCoder.defaultAbiCoder().encode(
    [
        "tuple(address consensusAddress,address operatorAddress,uint64 votingPower, bytes tendermintPublicKey)[]",
    ],
    [mainnet_validators]
);
console.log("validatorSetBytes:", validatorSetBytes);

exports = module.exports = {
    extraValidatorBytes: extraValidatorBytes,
    validatorSetBytes: validatorSetBytes,
};
