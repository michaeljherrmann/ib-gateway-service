const Sha1 = require('./sha1');
const OCRA = require('./ocra');
const BigInteger = require('jsbn').BigInteger;


describe('ocra', () => {
    test('can create shared secret key', () => {
        const bigK = new BigInteger('369795256452943965289304065253629202715073801757', 10);
        const IMEI = '48f8ede2193efa5f';

        const sk = Sha1.hashFromHex(bigK.toString(16));
        const ocraKey = Sha1.hash(sk, IMEI);

        const expected = '6574bf9b3cd79698e346fbb499d1213ea05ebc44';
        expect(ocraKey).toEqual(expected);
    });
    test('works as expected', () => {
        const ocraSuite = 'OCRA-1:HOTP-SHA1-8:C-QN06-PSHA1';
        const ocraKey = 'f187d2608a56467df1cb17b123ce2cef5428fc70';
        const counter = '1';
        const challenge = 174838;
        const pin = '1234';

        const sha1Pin = Sha1.hash(pin);
        const hexChallenge = challenge.toString(16);

        const response = OCRA.generateOCRA(
            ocraSuite,
            ocraKey,
            counter,
            hexChallenge,
            sha1Pin
        );

        const expected = '73566858';
        expect(response).toEqual(expected);
    });
    test('works as expected with another input', () => {
        const ocraSuite = 'OCRA-1:HOTP-SHA1-8:C-QN06-PSHA1';
        const ocraKey = '6574bf9b3cd79698e346fbb499d1213ea05ebc44';
        const counter = '1';
        const challenge = 133449;
        const pin = '1234';

        const sha1Pin = Sha1.hash(pin);
        const hexChallenge = challenge.toString(16);

        const response = OCRA.generateOCRA(
            ocraSuite,
            ocraKey,
            counter,
            hexChallenge,
            sha1Pin
        );

        const expected = '77445017';
        expect(response).toEqual(expected);
    });
    test('works as expected again', () => {
        const ocraSuite = 'OCRA-1:HOTP-SHA1-8:C-QN06-PSHA1';
        const ocraKey = '6574bf9b3cd79698e346fbb499d1213ea05ebc44';
        const counter = '3';
        const challenge = 654321;
        const pin = '1234';
        const sessionInformation = '';
        const timeStamp = '';

        const sha1Pin = Sha1.hash(pin);
        const hexChallenge = challenge.toString(16);

        const response = OCRA.generateOCRA(
            ocraSuite,
            ocraKey,
            counter,
            hexChallenge,
            sha1Pin,
            sessionInformation,
            timeStamp
        );

        const expected = '84748978';
        expect(response).toEqual(expected);
    });
});
