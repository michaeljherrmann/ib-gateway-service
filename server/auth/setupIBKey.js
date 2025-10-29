const IBKeyAuthenticator = require('./IBKeyAuthenticator');
const prompt = require('prompt');
const fs = require('fs');
const path = require('path');

async function doSetup() {
    console.log('\n=================================');
    console.log('==== WELCOME TO IB KEY SETUP ====');
    console.log('=================================\n');
    console.log('This script communicates with the IB server to establish two factor authentication' +
        ' using IBKey.\nThis script returns a secret token which must be saved afterwards.\n');

    prompt.message = '';
    prompt.start();
    let schema = {
        properties: {
            proceed: {
                description: 'This will invalidate any previous IB Key auth (phone app), do you' +
                    ' wish to proceed? (Y/n)',
                required: false
            }
        }
    };
    const {proceed} = await prompt.get(schema);
    if (proceed !== 'Y') {
        return;
    }

    schema = {
        properties: {
            username: {
                description: 'Enter the account username',
                required: true
            },
            password: {
                description: 'Enter the account password',
                required: true,
                hidden: true
            }
        }
    };

    const {username, password} = await prompt.get(schema);

    schema = {
        properties: {
            pin: {
                description: 'Enter a PIN for IB Key authentication',
                required: true,
                pattern: /^\d+$/,
                message: 'PIN must contain only numbers'
            }
        }
    };
    const {pin} = await prompt.get(schema);

    const ocraKey = await IBKeyAuthenticator.setupIBKey({
        username,
        password,
        baseUrl: 'https://ndcdyn.interactivebrokers.com',
        pin
    });

    const authData = {
        pin: pin,
        ocra: ocraKey,
        counter: 2,
        attempts: 0,
    };

    const fileName = `ib-key-auth-${username}-${Date.now()}.json`;
    const filePath = path.join(process.cwd(), fileName);
    fs.writeFileSync(filePath, JSON.stringify(authData, null, 2));

    console.log('\n***************************');
    console.log('IB Key setup successful!');
    console.log('***************************\n');
    console.log(JSON.stringify(authData, null, 2));
    console.log(`\nAuth data saved to: ${filePath}\n`);
}

console.clear();
doSetup().catch(error => {
    console.error(error);
});
