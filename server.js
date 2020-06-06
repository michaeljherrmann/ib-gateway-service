const bodyParser = require('body-parser');
const express    = require('express');
const kill       = require('tree-kill');
const proxy      = require('http-proxy-middleware');
const puppeteer  = require('puppeteer');
const { spawn }  = require('child_process');

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

// configure app to use bodyParser
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// API ROUTES
// =============================================================================
const router = express.Router();

router.route('/service')
    // POST
    // starts the IB gateway
    .post((req, res) => {
        startIBGateway().then(() => {
            startLockResolve();
            startLock = null;
            res.status(200).json('OK');
        }).catch((err) => {
            startLockReject();
            startLock = null;
            res.status(400).json('Error launching gateway: ' + err)
        });
    })

    // PUT
    // authenticates the ib gateway using the credentials passed in
    // body: { username: <USERNAME>, password: <PASSWORD> }
    .put((req, res) => {
        doAuth(req.body.username, req.body.password).then(() => {
            authLockResolve();
            authLock = null;
            res.status(200).json('OK');
        }).catch((err) => {
            authLockReject();
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
const proxyOptions = {
    target: IB_GATEWAY,
    ws: true, // proxy websockets
    secure: false, // don't verify ssl certs
    pathRewrite: {
        '^/api/gateway': '', // remove base api path
    },
    logLevel: LOG_LEVEL,
};
app.use('/api/gateway', proxy(proxyOptions));


// START THE SERVICE
// =============================================================================
app.listen(IB_GATEWAY_SERVICE_PORT);
console.log('Magic happens on PORT:' + IB_GATEWAY_SERVICE_PORT);

// PUPPETEER-CHROME INTERACTION
// =============================================================================
let authLock;
let authLockResolve;
let authLockReject;
async function doAuth(username, password) {
    if (!gateway) {
        throw new Error('IB gateway needs to be first started before trying to login');
    }

    if (authLock) {
        // another request already started authentication, just wait for that
        console.log('Already an ongoing auth request, waiting on that');
        await authLock;
        return;
    }
    // grab the lock
    authLock = new Promise((resolve, reject) => {
        authLockResolve = resolve;
        authLockReject = reject;
    });

    const browser = await puppeteer.launch({
        executablePath: 'google-chrome-unstable',
        headless: true,
        args: ['--no-sandbox'],
        ignoreHTTPSErrors: true, // ssl cert not valid for ib gateway
    });

    // Open login page
    const page = await browser.newPage();
    await page.goto(IB_GATEWAY);

    // Submit credentials
    await page.type('#user_name', username);
    await page.type('#password', password);
    await page.click('#submitForm');

    // Wait for redirect
    await page.waitForNavigation();

    // Verify
    let successMessage = await page.evaluate(() => document.body.innerText);

    browser.close();

    if (successMessage !== 'Client login succeeds') {
        throw Error('Login could not be verified! msg: ' + successMessage);
    }
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

    console.log('Starting IB Gateway');
    gateway = spawn(IB_GATEWAY_BIN, [IB_GATEWAY_CONF]);
    gateway.stdout.on('data', log);
    gateway.stderr.on('data', warn);
    gateway.on('exit', function (code) {
      console.log('IB Gateway exited with code ' + code);
      gateway = null;
    });

    // wait for 10s to allow process to start
    return new Promise(resolve => setTimeout(resolve, 10000));
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
