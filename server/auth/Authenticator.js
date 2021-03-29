const SecureRandom = require('jsbn').SecureRandom;
const BigInteger = require('jsbn').BigInteger;
const axios = require('axios').default;
const axiosCookieJarSupport = require('axios-cookiejar-support').default;
const tough = require('tough-cookie');
const https = require('https');
const parseStringPromise = require('xml2js').parseStringPromise;
const NodeRSA = require('node-rsa');

const Sha1 = require('./sha1');
const Sms = require('./sms');


const ONE = new BigInteger("1", 16);
const TWO = new BigInteger("2", 16);
const THREE = new BigInteger("3", 16);
const PATH = '/sso/Authenticator';
const DISPATCHER_PATH = '/sso/Dispatcher';

// SF_VERSION, only support "1" for now, since that seems to be in use
const VERSION = 1;

//SF types
const SSC = "3";
const IBKEY_ANDROID = "5.2a";
const IBKEY_IOS = "5.2i";
const BANK_KEY = "5.3";
const DSC = "4.1";
const ALPINE = "4";
const DSC_PLUS = "5.1";
const PLAT_GOLD = "5";
const TSC = "6";
const SMS = "4.2";


class Authenticator {
    static SMS = SMS;
    // static IBKEY_ANDROID = IBKEY_ANDROID; TODO
    // static IBKEY_IOS = IBKEY_ANDROID; TODO
    #username = '';
    #password = '';
    #rng = new SecureRandom();
    #suppLongPwd = false;
    #isPaper = null;
    #startDate = null;

    // Diffie–Hellman
    #N = new BigInteger("d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43", 16);
    #g = new BigInteger("2", 10);
    /** @type {BigInteger} */
    #a = null;
    /** @type {BigInteger} */
    #A = null;

    // RSA server
    #proto = '6';
    #hash = 'SHA1';
    /** @type {BigInteger} */
    #salt = null;
    /** @type {BigInteger} */
    #B = null;
    #submitEnckx = false;
    #serverRsaKey = new NodeRSA();
    #k = null;

    // complete authentication
    #x = null;
    #u = null;
    #Sc = null;
    #K = null;
    #M = '0';
    #secondFactorMethod = null;

    // session
    #M2 = null;
    #serverM2=null;
    #sessionKey = null;

    static async doAuth({username, password, baseUrl, secondFactorMethod}) {
        const a = new Authenticator(username, password, baseUrl, secondFactorMethod);
        await a.initialize();
        return await a.completeAuthentication();
    }

    constructor(username, password, baseUrl, secondFactorMethod = SMS) {
        this.#secondFactorMethod = secondFactorMethod;
        this.#username = username;
        this.#password = password;
        this.session = axios.create({
            baseURL: baseUrl,
            withCredentials: true,
            httpsAgent: new https.Agent({
                rejectUnauthorized: false,
                keepAlive: true,
            }),
        });

        // Set up the cookie jar
        axiosCookieJarSupport(this.session);
        this.session.defaults.jar = new tough.CookieJar();
        this.session.defaults.ignoreCookieErrors = true;

        // encryption set up
        this.#A = this._randomizeA();
        this.#serverRsaKey.setOptions({
            encryptionScheme: 'pkcs1',
        });
    }

    async initialize(secondTry) {
        if (!secondTry) {
            console.log('Authenticator initializing');
        }

        this.#startDate = new Date();
        // GET to the base url to set initial cookies
        await this.session.get('/');

        // create the ssoId cookie
        const expDate = new Date();
        expDate.setTime(expDate.getTime() + (60 * 60 * 24 * 365 * 10 * 1000)); // 10 years
        const ssoId = Math.random().toString(36).substring(2) + expDate.getTime().toString(36);
        const cookie = new tough.Cookie({
            key: 'SBID',
            value: ssoId,
            expires: expDate,
        });
        this.session.defaults.jar.setCookieSync(cookie, this.session.defaults.baseURL);

        // Initialize the shared key for rsa
        const data = new URLSearchParams();
        data.append('ACTION', 'INIT');
        data.append('APP_NAME', '');
        data.append('MODE', 'NORMAL');
        data.append('FORCE_LOGIN', '');
        data.append('USER', this.#username);
        data.append('ACCT', '');
        data.append('A', this.#A.toString(16));
        const response = await this.session.post(this.path, data);
        const requiresInitializeAgain = await this._parseIbAuthResponse(response);
        if (requiresInitializeAgain) {
            if (secondTry) {
                throw new Error(`initialize failed after second try: ${response.data}`);
            }
            await this.initialize(true);
            return;
        }

        this.#k = this._calculate_k();
    }

    async completeAuthentication() {
        this.#x = this._calculate_x(this.username, this.password, this.#salt);
        this.#u = this._calculate_u(this.#N, this.#A, this.#B);
        this.#Sc = this._calculate_client_secret(this.#g, this.#N, this.#B, this.#x, this.#u, this.#a, this.#k);
        this.#K = this._calculate_K(this.#Sc);
        this.#M = this._calculate_M(this.#N, this.#g, this.username, this.#salt, this.#A, this.#B, this.#K);

        const data = new URLSearchParams();
        data.append('ACTION', 'COMPLETEAUTH');
        data.append('APP_NAME', '');
        data.append('USER', this.username);
        data.append('ACCT', '');
        data.append('M1', this.#M);
        data.append('VERSION', VERSION.toString());
        if (this.#submitEnckx) {
            const ekx = this.#serverRsaKey.encrypt(this.#K, 'hex', 'utf8');
            data.append('EKX', ekx);
        }

        const response = await this.session.post(this.path, data);
        return await this._parseCompleteAuthentication(response);
    }

    get username() {
        return this.#username.toLowerCase();
    }

    get password() {
        if (this.#suppLongPwd) {
            return this.#password;
        }
        else {
            return this.#password.substr(0, 8);
        }
    }

    get path() {
        return PATH + '?' + Math.floor(Math.random()*100001);
    }

    _randomizeA() {
        const bytes = 32;
        this.#a = new BigInteger(8 * bytes, this.#rng);
        if (this.#a.compareTo(this.#N) >= 0) {
            this.#a = this.#a.mod(this.#N.subtract(ONE));
        }

        if (this.#a.compareTo(TWO) < 0) {
            this.#a = TWO;
        }

        return this.#g.modPow(this.#a, this.#N);
    }

    async _parseIbAuthResponse(response) {
        const xml = await parseStringPromise(response.data);
        const data = xml.ib_auth_res.ini_params[0];

        if (data.paper) {
            const paper = data.paper[0];
            this.#isPaper = (paper === 'true');
        }

        const newg = new BigInteger(data.g[0], 10);
        const newN = new BigInteger(data.N[0], 16);
        this.#proto = data.proto[0];
        this.#hash = data.hash[0];
        this.#salt = new BigInteger(data.s[0], 16);
        this.#B = new BigInteger(data.B[0], 16);
        this.#suppLongPwd = (data.lp[0] === 'true');

        this.#submitEnckx = true;
        this.#serverRsaKey.importKey({
            n: Buffer.from(data.rsapub[0], 'hex'),
            e: 3,
        }, 'components-public');

        let requiresInitializeAgain = false;
        if (!this.#g.equals(newg)) {
          requiresInitializeAgain = true;
          this.#g = newg;
        }
        if(!this.#N.equals(newN)) {
            requiresInitializeAgain = true;
            this.#N = newN;
        }
        return requiresInitializeAgain;
    }

    async _parseCompleteAuthentication(response) {
        const xml = await parseStringPromise(response.data);
        const data = xml.ib_auth_res.ini_params[0];

        if (data.M2[0]) {
            this.#serverM2 = data.M2[0];
        }
        this.#M2 = this._calculate_M2(this.#A, this.#M, this.#K);
        if (this.#M2 !== this.#serverM2) {
            if (xml.ib_auth_res.auth_info[0].reached_max_login[0] === "true") {
                throw new Error('Invalid username and password combination, reached max limit');
            }
            throw new Error('Invalid username and password combination');
        }

        this.#sessionKey = this._calculateSessionKey(this.#B, this.#K);
        this._storeSessionKey(this.#sessionKey);

        const sfTypes = xml.ib_auth_res.sftypes;
        if (sfTypes) {
            // two factor
            const available = sfTypes[0].split(',');
            if (available.length > 1) {
                console.warn('more than one two factor available, using SMS');
            }
            if (available.indexOf(this.#secondFactorMethod) === -1) {
                throw new Error(`${this.#secondFactorMethod} is not valid for the account, only: ${available} are available`);
            }
            // trigger sms to be sent
            return await this._completeTwoFactorAuthentication(this.#secondFactorMethod);
        }
        else {
            return await this._finish('');
        }
    }

    async _completeTwoFactorAuthentication(selectedSF) {
        const data = new URLSearchParams();
        data.append('ACTION', 'COMPLETEAUTH_1');
        data.append('APP_NAME', '');
        data.append('USER', this.#username);
        data.append('ACCT', '');
        data.append('M1', this.#M);
        data.append('VERSION', VERSION.toString());
        data.append('SF', selectedSF);
        const response = await this.session.post(this.path, data);
        const xml = await parseStringPromise(response.data);
        const twoFactorType = xml.ib_auth_res.two_factor[0].type[0];
        return await this._authenticateTwoFactor(twoFactorType, SMS);
    }

    async _authenticateTwoFactor(twoFactorType, selectedSF) {
        let challenge = '';
        if (selectedSF === SMS) {
            challenge = await Sms.getChallenge(this.#startDate);
        }
        if (twoFactorType === 'IBTK') {
            throw new Error('case not handled');
        }

        const data = new URLSearchParams();
        data.append('ACTION', 'COMPLETETWOFACT');
        data.append('APP_NAME', '');
        data.append('USER', this.#username);
        data.append('ACCT', '');
        data.append('RESPONSE', challenge);
        data.append('VERSION', VERSION.toString());
        data.append('SF', selectedSF);
        await this.session.post(this.path, data);
        return await this._finish(challenge);
    }

    async _finish(challenge) {
        const data = new URLSearchParams();
        data.append('user_name', this.#username);
        data.append('password', 'xxxxxxxxxxxxxxxxxxxxxxxx');
        data.append('chlginput', challenge);
        data.append('loginType', '0');
        data.append('forwardTo', '22');
        data.append('M1', this.#M);
        data.append('M2', this.#M2);
        const response = await this.session.post(DISPATCHER_PATH, data);
        return response.data === 'Client login succeeds';
    }

    _calculate_k() {
        let hashIn = "";
        let nhex;
        let ghex;
        let ktmp;
        if (this.#proto === "3")
            return ONE;
        else if (this.#proto === "6")
            return THREE;
        else {
            /* k = H(N || g) */
            nhex = String(this.#N.toString(16));
            if ((nhex.length & 1) === 0) {
                hashIn += nhex;
            } else {
                hashIn += "0" + nhex;
            }
            ghex = String(this.#g.toString(16));
            hashIn += nzero(nhex.length - ghex.length);
            hashIn += ghex;
            ktmp = new BigInteger(Sha1.hashFromHex(hashIn), 16);
            if (ktmp.compareTo(this.#N) < 0) {
                return ktmp;
            }
            else {
                return ktmp.mod(this.#N);
            }
        }
    }

    _calculate_x(username, password, salt) {
        let input = username + ':' + password;
        const innerHash = Sha1.hash(input);
        input = this._verifyHexVal(salt) + innerHash;
        const outerHash = Sha1.hashFromHex(input);
        const x = new BigInteger(outerHash, 16);
        if (x.compareTo(this.#N) < 0) {
            return x;
        }
        else {
            return x.mod(N.subtract(ONE));
        }
    }

    /**
     * proto-3: first 32 bits (MSB) of SHA-1(B)
     * proto-6(a): SHA-1(A || B)
     * @param {BigInteger} N
     * @param {BigInteger} A
     * @param {BigInteger} B
     */
    _calculate_u(N, A, B) {
        let aHex;
        let bHex = B.toString(16);
        let hashIn = "";
        let u;
        let nLen;
        if (this.#proto !== "3") {
            aHex = A.toString(16);
            if (this.#proto === "6") {
                if ((aHex.length & 1) === 0) {
                    hashIn += aHex;
                }
                else {
                    hashIn += "0" + aHex;
                }
            }
            else { /* 6a requires left-padding */
                nLen = 2 * ((N.bitLength() + 7) >> 3);
                hashIn += this._nzero(nLen - aHex.length) + aHex;
            }
        }
        if (this.#proto === "3" || this.#proto === "6") {
            if ((bHex.length & 1) === 0) {
                hashIn += bHex;
            }
            else {
                hashIn += "0" + bHex;
            }
        }
        else { /* 6a requires left-padding; nLen already set above */
            hashIn += this._nzero(nLen - bHex.length) + bHex;
        }
        if (this.#proto === "3") {
            const int = Sha1.hashFromHex(hashIn).substr(0, 8);
            u = new BigInteger(int, 16);
        }
        else {
            u = new BigInteger(Sha1.hashFromHex(hashIn), 16);
        }

        if (u.compareTo(N) < 0) {
            return u;
        }
        else {
            return u.mod(N.subtract(ONE));
        }
    }

    /**
     * Secret = (B - kg^x) ^ (a + ux) (mod N)
     */
    _calculate_client_secret(g, N, B, x, u, a, k) {
        const bx = g.modPow(x, N);
        const bTmp = B.add(N.multiply(k)).subtract(bx.multiply(k)).mod(N);
        return bTmp.modPow(x.multiply(u).add(a), N);
    }

    /**
     * hash of client secret
     */
    _calculate_K(clientSecret) {
        return Sha1.hashFromHex(this._verifyHexVal(clientSecret));
    }

    _calculate_M(N, g, username, salt, A, B, K) {
        let hashIn = "";
        let h_n = Sha1.hashFromHex(this._verifyHexVal(N));
        let h_g = Sha1.hashFromHex(this._verifyHexVal(g));
        h_n = new BigInteger(this._verifyHexVal(h_n), 16);
        h_g = new BigInteger(this._verifyHexVal(h_g), 16);

        const h_xor = this._verifyHexVal(h_n.xor(h_g).toString(16));
        const h_I = Sha1.hash(username);

        const sHex = this._verifyHexVal(salt);

        hashIn += h_xor;
        hashIn += h_I;
        hashIn += sHex;
        hashIn += this._verifyHexVal(A);
        hashIn += this._verifyHexVal(B);
        hashIn += this._verifyHexVal(K);
        return this._verifyHexVal(Sha1.hashFromHex(hashIn));
    }

    _calculate_M2(A, M, K) {
        let hashIn = '';
        hashIn += this._verifyHexVal(A);
        hashIn += this._verifyHexVal(M);
        hashIn += this._verifyHexVal(K);
        return Sha1.hashFromHex(hashIn);
    }

    _calculateSessionKey(B, K) {
        let hashIn = '';
        hashIn += this._verifyHexVal(B);
        hashIn += this._verifyHexVal(K);
        return Sha1.hashFromHex(hashIn);
    }

    _storeSessionKey(sessionKey) {
        const cookie = new tough.Cookie({
            key: 'XYZAB_AM.LOGIN',
            value: sessionKey,
        });
        this.session.defaults.jar.setCookieSync(cookie, this.session.defaults.baseURL);
    }

    /**
     * ensure hex value is an even number
     * @param {BigInteger|string} hv
     */
    _verifyHexVal(hv) {
        let hashIn = '';
        const hexStr = hv.toString(16);
        if ((hexStr.length & 1) === 0) {
            hashIn += hexStr;
        } else {
            hashIn += "0" + hexStr;
        }

        if (hashIn.charAt(0) === "0" && hashIn.charAt(1) === "0") {
            hashIn = hashIn.substring(2, hashIn.length);
        }
        return hashIn;
    }

    /**
     * Returns a string with n zeroes in it
     */
    _nzero(n) {
        if (n < 1) {
            return "";
        }
        const t = this._nzero(n >> 1);
        if ((n & 1) === 0) {
            return t + t;
        }
        else {
            return t + t + "0";
        }
    }


}

module.exports = Authenticator;
