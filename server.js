const bodyParser = require('body-parser');
const express    = require('express');
const kill       = require('tree-kill');
const puppeteer  = require('puppeteer');
const { spawn }  = require('child_process');

// consts from environment
const IBG_SERVICE_PORT = process.env.IBG_SERVICE_PORT || 5050;

const IB_GATEWAY_BIN = process.env.IB_GATEWAY_BIN;
const IB_GATEWAY_CONF = process.env.IB_GATEWAY_CONF;
const IB_GATEWAY_DOMAIN = process.env.IB_GATEWAY_DOMAIN || 'localhost';
const IB_GATEWAY_PORT = process.env.IB_GATEWAY_PORT || 5000;
const IB_GATEWAY = 'https://' + IB_GATEWAY_DOMAIN + ':' + IB_GATEWAY_PORT;

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
            res.status(200).json('OK');
        }).catch((err) => {
            res.status(400).json('Error launching gateway: ' + err)
        });
    })

    // PUT
    // authenticates the ib gateway using the credentials passed in
    // body: { username: <USERNAME>, password: <PASSWORD> }
    .put((req, res) => {
        doAuth(req.body.username, req.body.password).then(() => {
            res.status(200).json('OK');
        }).catch((err) => {
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
app.use('/ibg', router);


// START THE SERVICE
// =============================================================================
app.listen(IBG_SERVICE_PORT);
console.log('Magic happens on PORT:' + IBG_SERVICE_PORT);

// PUPPETEER-CHROME INTERACTION
// =============================================================================
async function doAuth(username, password) {
    if (!gateway) {
        throw new Error('IB gateway needs to be first started before trying to login');
    }

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

async function startIBGateway() {
    if (gateway) {
        // gateway is already running
        return;
    }

    if (!IB_GATEWAY_BIN || !IB_GATEWAY_CONF) {
        throw new Error('Missing bin and/or conf for ib gateway');
    }

    gateway = spawn(IB_GATEWAY_BIN, [IB_GATEWAY_CONF]);
    gateway.stdout.on('data', log);
    gateway.stderr.on('data', warn);

    // wait for 5s to allow process to start
    return new Promise(resolve => setTimeout(resolve, 5000));
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
                resolve();
            }
        });
    });
}
