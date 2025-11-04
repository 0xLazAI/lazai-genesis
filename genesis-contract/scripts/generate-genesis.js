const program = require('commander');
const nunjucks = require('nunjucks');
const fs = require('fs');
const web3 = require('web3');

const validators = require('./validators');
const init_holders = require('./init_holders');

program.version('0.0.1');
program.option('-c, --chainId <chainId>', 'chain id', '714');
program.option('-o, --output <output-file>', 'Genesis json file', './genesis.json');
program.option('-t, --template <template>', 'Genesis template json', './genesis-template.json');
program.parse(process.argv);

// get byte code from compiled contract
function readByteCode(key, contractFile) {
    return new Promise((resolve, reject) => {
        fs.readFile(`${contractFile}`, 'utf8', (err, data) => {
            if (err) {
                reject(new Error('Error reading file: ' + err.message));
                return;
            }

            try {
                const jsonObj = JSON.parse(data);
                const compiledData = jsonObj['deployedBytecode']['object'];

                resolve({
                    key: key,
                    compiledData: compiledData,
                });
            } catch (parseError) {
                reject(new Error('Error parsing JSON: ' + parseError.message));
            }
        });
    });
}

// compile files
Promise.all([
    readByteCode('validatorContract', 'out/ValidatorSet.sol/ValidatorSet.json'),
    readByteCode('systemRewardContract', 'out/SystemReward.sol/SystemReward.json'),
    readByteCode('slashContract', 'out/SlashIndicator.sol/SlashIndicator.json'),
    readByteCode('govHub', 'out/GovHub.sol/GovHub.json'),
    readByteCode('stakeHub', 'out/StakeHub.sol/StakeHub.json'),
    readByteCode('stakeCredit', 'out/StakeCredit.sol/StakeCredit.json'),
    readByteCode('governor', 'out/Governor.sol/Governor.json'),
    readByteCode('govToken', 'out/GovToken.sol/GovToken.json'),
    readByteCode('timelock', 'out/Timelock.sol/Timelock.json'),
    readByteCode('create2deployer', 'pre_deploy_contracts/create2deployer.json'),
    readByteCode('deterministicdeploymentproxy', 'pre_deploy_contracts/deterministicdeploymentproxy.json'),
    readByteCode('multicall3', 'pre_deploy_contracts/multicall3.json'),
    readByteCode('gnosissafe', 'pre_deploy_contracts/gnosissafe.json'),
    readByteCode('gnosissafel2', 'pre_deploy_contracts/gnosissafel2.json'),
    readByteCode('multisendcallonly', 'pre_deploy_contracts/multisendcallonly.json'),
    readByteCode('multisend', 'pre_deploy_contracts/multisend.json'),
    readByteCode('permit2', 'pre_deploy_contracts/permit2.json'),
    readByteCode('entrypoint', 'pre_deploy_contracts/entrypoint.json'),
    readByteCode('sendercreator', 'pre_deploy_contracts/sendercreator.json'),
    readByteCode('weth', 'pre_deploy_contracts/weth.json'),
]).then((result) => {
    const data = {
        chainId: program.chainId,
        initHolders: init_holders,
        extraData: web3.utils.bytesToHex(validators.extraValidatorBytes),
    };

    result.forEach((r) => {
        data[r.key] = r.compiledData;
    });

    const templateString = fs.readFileSync(program.template).toString();
    const resultString = nunjucks.renderString(templateString, data);
    fs.writeFileSync(program.output, resultString);
});
