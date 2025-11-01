const bodyParser = require('body-parser');
const express    = require('express');
const fs         = require('fs');
const https      = require('https');
const kill       = require('tree-kill');
const path       = require('path')
const { spawn }  = require('child_process');
const Sms = require("./auth/sms");
const auth       = require('./auth').Authenticator;
const ibkey      = require('./auth').IBKeyAuthenticator;
const TwoFactorError = require('./auth').TwoFactorError;

// consts from environment
const IB_GATEWAY_SERVICE_PORT = process.env.IB_GATEWAY_SERVICE_PORT || 5050;

const DATA_STORE_PATH = process.env.IB_GATEWAY_DATA_STORE_PATH || '/tmp/ib_gateway_data/'
const IB_AUTH_MAX_ATTEMPTS = process.env.IB_AUTH_MAX_ATTEMPTS || 4;
const IB_AUTH_USE_IBKEY = !!process.env.IB_AUTH_USE_IBKEY || false;
const IB_AUTH_MAX_COUNTER = process.env.IB_AUTH_MAX_COUNTER || 95;

// Validate IB_AUTH_MAX_COUNTER, for some reason it stops working after 100
if (IB_AUTH_MAX_COUNTER > 100) {
    throw new Error(`IB_AUTH_MAX_COUNTER must be less than or equal to 100 (current value: ${IB_AUTH_MAX_COUNTER})`);
}

const IB_GATEWAY_BIN = process.env.IB_GATEWAY_BIN;
const IB_GATEWAY_CONF = process.env.IB_GATEWAY_CONF;
const IB_GATEWAY_DOMAIN = process.env.IB_GATEWAY_DOMAIN || 'localhost';
const IB_GATEWAY_PORT = process.env.IB_GATEWAY_PORT || 5000;
const IB_GATEWAY_SCHEME = process.env.IB_GATEWAY_SCHEME || 'https://';
const IB_GATEWAY = IB_GATEWAY_SCHEME + IB_GATEWAY_DOMAIN + ':' + IB_GATEWAY_PORT;

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
    // body: { username: <USERNAME>, password: <PASSWORD>, totpSecret: <TOTP_SECRET> (optional) }
    .put((req, res) => {
        if (!req.body.username || !req.body.password) {
            res.status(400).json('username and password are required');
        }
        doAuth(req.body.username, req.body.password, req.body.totpSecret).then((data) => {
            authLockResolve(data);
            authLock = null;
            lockedUntil = null;
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

// START THE SERVICE
// =============================================================================
app.listen(IB_GATEWAY_SERVICE_PORT);
console.log('Magic happens on PORT:' + IB_GATEWAY_SERVICE_PORT);

// IB AUTH
// =============================================================================
let authLock;
let authLockResolve;
let authLockReject;
let lockedUntil;

function generatePin() {
    return (Math.floor(Math.random() * (999999 - 1000) ) + 1000).toString();
}

async function doAuth(username, password, totpSecret) {
    if (!gateway) {
        throw new Error('IB gateway needs to be first started before trying to login');
    }

    if (lockedUntil) {
        const now = Date.now();
        if (now >= lockedUntil) {
            lockedUntil = null;
        }
        else {
            const unlocks = Math.ceil((lockedUntil - now) / 1000);
            throw new Error(`Auth is in backoff, try again in ${unlocks}s`)
        }
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

    // data file to store auth data
    const dataFile = path.join(DATA_STORE_PATH, 'data.json');
    let authDataStr;
    try {
        authDataStr = fs.readFileSync(dataFile, 'utf8');
    }
    catch (e) {
        console.log(`creating auth data file: ${dataFile}`);
        authDataStr = JSON.stringify({
            pin: generatePin(),
            ocra: null,
            counter: 2,
            attempts: 0,
        });
        fs.mkdirSync(DATA_STORE_PATH, {recursive: true});
        fs.writeFileSync(dataFile, authDataStr);
    }
    const authData = JSON.parse(authDataStr);

    // track login attempts to prevent accidentally locking out if too many failed attempts
    authData.attempts += 1;


    // if login fails, how soon to allow another try
    const now = Date.now();
    switch (authData.attempts) {
        case 1: lockedUntil = now + 60 * 1000; break; // 1 min
        case 2: lockedUntil = now + 60 * 60 * 1000; break; // 1 hour
        default: lockedUntil = now + 6 * 60 * 60 * 1000; // 6 hours
    }

    try {
        if (parseInt(authData.attempts) > IB_AUTH_MAX_ATTEMPTS) {
            throw new Error(`Too many failed login attempts (${authData.attempts}), requires manual investigation and reset`);
        }

        let secondFactorMethod = auth.SMS;

        // Determine second factor method based on what's provided
        if (totpSecret) {
            console.log('Using TOTP as second factor');
            secondFactorMethod = auth.TOTP;
        }
        else if (IB_AUTH_USE_IBKEY) {
            console.log('Using IBKey as second factor');
            secondFactorMethod = auth.IBKEY_ANDROID;

            if (!authData.ocra || authData.counter >= IB_AUTH_MAX_COUNTER) {
                if (!Sms.hasCredentials()) {
                    throw new Error('SMS credentials are not set, cannot automatically setup IBKey');
                }
                console.log(`setting up IB Key, counter is at ${authData.counter}`);
                authData.ocra = await ibkey.setupIBKey({
                    username,
                    password,
                    baseUrl: 'https://ndcdyn.interactivebrokers.com',
                    pin: authData.pin,
                });
                authData.counter = 2;
            }
        }

        const success = await auth.doAuth({
            username,
            password,
            baseUrl: IB_GATEWAY,
            secondFactorMethod,
            ocraPin: authData.pin,
            ocraSecret: authData.ocra,
            ocraCounter: authData.counter,
            totpSecret: totpSecret,
        });
        authData.counter += 1;
        if (!success) {
            throw new Error('Login failed for an unknown reason');
        }
        authData.attempts = 0;
    }
    catch (e) {
        if (e instanceof TwoFactorError) {
            // If it's a two factor error, good chance the counter is out of date
            authData.counter += 1;
        }
        throw e;
    }
    finally {
        // save auth data
        fs.writeFileSync(dataFile, JSON.stringify(authData));
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
    for (let i = 0; i < 8; i++) {
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
