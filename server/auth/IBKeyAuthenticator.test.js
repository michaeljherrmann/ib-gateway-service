const BigInteger = require('jsbn').BigInteger;
const NodeRSA = require('node-rsa');

const IBKeyAuthenticator = require('./IBKeyAuthenticator');


const USERNAME = 'user';
const PASSWORD = 'pass';
const URL = ''; // https://localhost:5000
const IMEI = "48f8ede2193efa5f";

describe('IBKeyAuthenticator', () => {
    test('creates ocra key', () => {
        const auth = new IBKeyAuthenticator(USERNAME, PASSWORD, URL);
        const K = 'e8c81169b9e8bc40a7d0cd8bc6617c5171e61b87';

        const res = auth._createOcraKey(K, IMEI);

        const expected = 'ae7ea584ec7cfaffccca2a4238f8f1fb8e26d5da';
        expect(res).toEqual(expected);
    });

    test('generates challenge response', () => {
        const auth = new IBKeyAuthenticator(USERNAME, PASSWORD, URL);
        const pin = '1234';
        const counter = '1';
        const challenge = '708362'
        const algo = 'OCRA-1:HOTP-SHA1-8:C-QN06-PSHA1';
        const ocraKey = 'ae7ea584ec7cfaffccca2a4238f8f1fb8e26d5da';

        const res = auth._generateChallengeResponse(pin, counter, challenge, algo, ocraKey);

        const expected = '15632646';
        expect(res).toEqual(expected);
    });
});
