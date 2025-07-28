const IBKeyAuthenticator = require('./IBKeyAuthenticator');
const prompt = require('prompt');

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
    const ocraKey = await IBKeyAuthenticator.setupIBKey({
        username,
        password,
        baseUrl: 'https://ndcdyn.interactivebrokers.com',
    });

    console.log('***************************');
    console.log(`Here is your IB Key secret: ${ocraKey}`);
    console.log('***************************');
    console.log('You will need the pin you entered earlier and the OCRA counter starts at "2"');
}

console.clear();
doSetup().catch(error => {
    console.error(error);
});
