const init_holders = [
    // {
    //     // private key is 0x9b28f36fbd67381120752d6172ecdcf10e06ab2d9a1367aac00cdcd6ac7855d3, only use in dev
    //     address: '0x9fB29AAc15b9A4B7F17c3385939b007540f4d791',
    //     balance: BigInt('10000000000000000000000000').toString(16),
    // },
    {
        address: '0xddd8e974a417823966774e502235f8a936837803', // mainnet
        balance: BigInt('9999993000000000000000000').toString(16), // 9,999,993 metis
    },
    {
        address: '0xa7ECcdb9Be08178f896c26b7BbD8C3D4E844d9Ba', // mainnet
        balance: BigInt('5000000000000000000').toString(16), // hyperlane 5 metis
    },
    {
        address: '0x6e7F4E67048c40F48aD097dc850E6BeA19F3F351', // mainnet
        balance: BigInt('2000000000000000000').toString(16), // 2 metis
    },
];

exports = module.exports = init_holders;
