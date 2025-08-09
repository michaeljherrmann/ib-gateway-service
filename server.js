const bodyParser = require('body-parser');
const express    = require('express');
const https      = require('https');
const kill       = require('tree-kill');
const proxy      = require('http-proxy-middleware');
const puppeteer  = require('puppeteer');
const { spawn }  = require('child_process');
const twilio      = require('twilio');

// TODO: for now the proxy forwarding doesn't seem to work that well
//  the ib gateway rejects/doesn't respond to some of those requests
//  have to debug further, but maybe it has to do with header info?
//  for now just communicating directly to the ib gateway

// consts from environment
const LOG_LEVEL = process.env.IB_GATEWAY_LOG_LEVEL || 'info';
const IB_GATEWAY_SERVICE_PORT = process.env.IB_GATEWAY_SERVICE_PORT || 5050;

const IB_GATEWAY_BIN = process.env.IB_GATEWAY_BIN;
const IB_GATEWAY_CONF = process.env.IB_GATEWAY_CONF;
const IB_GATEWAY_DOMAIN = process.env.IB_GATEWAY_DOMAIN || 'localhost';
const IB_GATEWAY_PORT = process.env.IB_GATEWAY_PORT || 5000;
const IB_GATEWAY_SCHEME = process.env.IB_GATEWAY_SCHEME || 'https://';
const IB_GATEWAY = IB_GATEWAY_SCHEME + IB_GATEWAY_DOMAIN + ':' + IB_GATEWAY_PORT;

const TWILIO_ACCOUNT_SID = process.env.IB_AUTH_TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.IB_AUTH_TWILIO_AUTH_TOKEN;

// configure app to use bodyParser
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// API ROUTES
// =============================================================================
const router = express.Router();

router.route('/service')
    // GET
    // healthcheck endpoint
    .get((req, res) => {
        res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
    })

    // POST
    // starts the IB gateway
    .post((req, res) => {
        startIBGateway().then(() => {
            startLockResolve();
            startLock = null;
            res.status(200).json('OK');
        }).catch((err) => {
            startLockReject(err);
            startLock = null;
            res.status(400).json('Error launching gateway: ' + err)
        });
    })

    // PUT
    // authenticates the ib gateway using the credentials passed in
    // body: { username: <USERNAME>, password: <PASSWORD> }
    .put((req, res) => {
        doAuth(req.body.username, req.body.password).then((data) => {
            authLockResolve(data);
            authLock = null;
            res.status(200).json(data);
        }).catch((err) => {
            authLockReject && authLockReject(err);
            authLock = null;
            res.status(400).json('Error authenticating: ' + err);
        });
    })

    // DELETE
    // stops the IB gateway
    .delete((req, res) => {
        stopIBGateway().then(() => {
            res.status(200).json('OK');
        }).catch((err) => {
            res.status(400).json('Error stopping gateway: ' + err);
        });
    });


// // LOG REQUESTS
app.use((req, res, next) => {
    console.log(`IB GATEWAY SERVICE: ${req.method} ${req.originalUrl}`);
    next();
});


// REGISTER OUR ROUTES -------------------------------
app.use('/api', router);

// REGISTER PROXY ------------------------------------
// const proxyOptions = {
//     target: IB_GATEWAY,
//     ws: true, // proxy websockets
//     secure: false, // don't verify ssl certs
//     pathRewrite: {
//         '^/api/gateway': '', // remove base api path
//     },
//     logLevel: LOG_LEVEL,
// };
// app.use('/api/gateway', proxy(proxyOptions));


// START THE SERVICE
// =============================================================================
app.listen(IB_GATEWAY_SERVICE_PORT);
console.log('Magic happens on PORT:' + IB_GATEWAY_SERVICE_PORT);

// PUPPETEER-CHROME INTERACTION
// =============================================================================
let authLock;
let authLockResolve;
let authLockReject;
let browser;

async function handleTwoFactor(page, startDate) {
    const codeInputSelector = '#chlginput';
    await page.waitForSelector(codeInputSelector);

    console.log('Two factor authentication is required');
    const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

    async function getCode() {
        const messages = await client.messages.list({
            dateSentAfter: startDate,
            limit: 1,
        });
        if (messages.length !== 1) {
            throw new Error(`Twilio returned ${messages.length} messages`);
        }
        const message = messages[0];
        console.log('Retrieved message from twilio');
        const match = message.body.match(/\d{6}/);
        if (match === null) {
            throw new Error(`Could not extract code from message body: "${message.body}"`)
        }
        return match[0];
    }

    let err;
    for (let i = 0; i <= 5; i++) {
        console.log(`Checking for auth SMS in ${i}s`)
        await new Promise(resolve => setTimeout(resolve, i * 1000));
        try {
            const code = await getCode();
            await page.type(codeInputSelector, code);
            await page.click('#submitForm');
            return page.waitForNavigation();
        }
        catch (e) {
            err = e;
        }
    }

    // could not complete two factor after retries
    throw new Error(`Two factor authentication could not complete in time due to ${err}`);
}

async function doAuth(username, password) {
    if (!gateway) {
        throw new Error('IB gateway needs to be first started before trying to login');
    }

    if (authLock) {
        // another request already started authentication, just wait for that
        console.log('Already an ongoing auth request, waiting on that');
        return authLock;
    }
    // grab the lock
    authLock = new Promise((resolve, reject) => {
        authLockResolve = resolve;
        authLockReject = reject;
    });
    authLock.catch(() => {});

    browser = await puppeteer.launch({
        executablePath: 'google-chrome-unstable', // uncomment to use chrome
        headless: true,
        args: ['--no-sandbox'],
        ignoreHTTPSErrors: true, // ssl cert not valid for ib gateway
    });

    let successMessage = '';
    try {
        // Open login page
        const startDate = new Date();
        const page = await browser.newPage();
        await page.goto(IB_GATEWAY);

        // Submit credentials
        await page.type('#user_name', username);
        await page.type('#password', password);
        await page.click('#submitForm');

        // Wait for redirect to happen or for two factor to complete
        await Promise.race([
            page.waitForNavigation(),
            handleTwoFactor(page, startDate),
        ]);

        // Verify
        successMessage = await page.evaluate(() => document.body.innerText);
    }
    finally {
        await browser.close();
        browser = null;
    }

    if (successMessage !== 'Client login succeeds') {
        throw Error('Login could not be verified! msg: ' + successMessage);
    }

    // Wait for gateway to be authenticated
    const isGatewayAuthenticated = () => {
        return new Promise((resolve, reject) => {
            console.log('checking if gateway is authenticated')
            const options = {
                hostname: IB_GATEWAY_DOMAIN,
                port: IB_GATEWAY_PORT,
                path: '/v1/api/iserver/auth/status',
                method: 'GET',
                rejectUnauthorized: false, // disable SSL check
            };
            const req = https.request(options, (res) => {
                console.log('statusCode:', res.statusCode);
                console.log('headers:', res.headers);
                let body='';
                res.on('data', (chunk) => {
                    body += chunk;
                });
                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 400) {
                        const data = JSON.parse(body);
                        console.log(body);
                        if (data.authenticated) {
                            resolve(data);
                        }
                        else {
                            reject(new Error(body));
                        }
                    }
                    else {
                        reject(new Error(res.statusCode));
                    }
                });

            }).on('error', (e) => {
                console.error(e);
                reject(e);
            });
            req.setHeader('user-agent', 'ib-gateway-service');
            req.setHeader('content-type', 'application/json');
            req.setHeader('accept', 'application/json');
            req.end();
        });
    }

    let err;
    for (let i = 0; i < 10; i++) {
        console.log(`Gateway is not authenticated yet, checking again in ${i}s`)
        await new Promise(resolve => setTimeout(resolve, i * 1000));

        try {
            return await isGatewayAuthenticated();
        }
        catch (e) {
            err = e;
        }
    }
    throw new Error(`Gateway did not authenticate in time due to ${err}`);
}

// IB GATEWAY
// =============================================================================
let gateway = null;

function log(msg) {
    console.log('stdout: ' + msg);
}

function warn(msg) {
    console.warn('stdout: ' + msg);
}

let startLock;
let startLockResolve;
let startLockReject;
async function startIBGateway() {
    if (gateway) {
        // gateway is already running
        return;
    }

    if (!IB_GATEWAY_BIN || !IB_GATEWAY_CONF) {
        throw new Error('Missing bin and/or conf for ib gateway');
    }

    if (startLock) {
        // another request already started the gateway, just wait for that
        console.log('Already an ongoing start request, waiting on that');
        return startLock;
    }
    // grab the lock
    startLock = new Promise((resolve, reject) => {
        startLockResolve = resolve;
        startLockReject = reject;
    });
    startLock.catch(() => {});

    console.log('Starting IB Gateway');
    gateway = spawn(IB_GATEWAY_BIN, [IB_GATEWAY_CONF]);
    gateway.stdout.on('data', log);
    gateway.stderr.on('data', warn);
    gateway.on('exit', function (code) {
      console.log('IB Gateway exited with code ' + code);
      gateway = null;
    });

    const isGatewayUp = () => {
        return new Promise((resolve, reject) => {
            console.log('checking if gateway is up')
            const options = {
                hostname: IB_GATEWAY_DOMAIN,
                port: IB_GATEWAY_PORT,
                method: 'GET',
                rejectUnauthorized: false, // disable SSL check
            };
            https.request(options, (res) => {
                console.log('statusCode:', res.statusCode);
                console.log('headers:', res.headers);

                res.on('data', () => {});
                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 400) {
                        resolve();
                    }
                    else {
                        reject(new Error(res.statusCode));
                    }
                });

            }).on('error', (e) => {
                console.error(e);
                reject(e);
            }).end();
        });
    }

    let err;
    for (let i = 1; i < 10; i++) {
        console.log(`Gateway is not up yet, checking again in ${i}s`)
        await new Promise(resolve => setTimeout(resolve, i * 1000));

        try {
            return await isGatewayUp();
        }
        catch (e) {
            err = e;
        }
    }
    throw new Error(`Gateway did not start up in time due to ${err}`);
}


async function stopIBGateway() {
    if (browser) {
        // kill the browser too if it's still open
        browser.close();
        browser = null;
    }
    if (!gateway) {
        // no gateway or it was already killed
        return;
    }

    gateway.stdout.off('data', log);
    gateway.stderr.off('data', warn);

    return new Promise((resolve, reject) => {
        // Kill whole subtree
        kill(gateway.pid, 'SIGTERM', (err) => {
            if (err) {
                reject(err);
            }
            else {
                gateway = null;
                console.log('IB Gateway stopped');
                resolve();
            }
        });
    });
}
