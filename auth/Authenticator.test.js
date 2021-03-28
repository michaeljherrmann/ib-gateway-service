const BigInteger = require('jsbn').BigInteger;
const NodeRSA = require('node-rsa');

const Authenticator = require('./Authenticator');


const USERNAME = 'user';
const PASSWORD = 'pass';
const URL = ''; // https://localhost:5000

describe('Authenticator', () => {
    test.skip('rsa encryption', () => {
        const rsa = new NodeRSA();
        rsa.setOptions({
            // environment: 'browser',
            // encryptionScheme: 'pkcs1',
            // signingScheme: 'pkcs1',
        })
        const pubKey = 'AA9BEF363E28DE8CFCEFA08861AC588E582EED93416ED436BE75CEDBB41F262CE37613A18F87D13B2F28621F9D7B9AC6AF3310E88C4C6EBEFCA22214419E3C3F6F44ED7538339B81410E1EC73565B201031B74DA3DA9C3F9453DFB79912315877D63AEB7BDFF28C9124FC11D5B669553646D40CEE23754E5D8FE726788276059';
        const e = 3;
        const K = '6606a738b16f296c6110370618dd9ac761005b5b';
        rsa.importKey({
            n: Buffer.from(pubKey, 'hex'),
            e: e,
        }, 'components-public');

        const res = rsa.encrypt(Buffer.from(K, 'hex'), 'hex', 'utf8')
        // const res = rsa.encrypt(K, 'hex', 'utf8')

        const expected = '451cc0c20b883cb29b266bc3f68693ce790025417bfd4d4e6d67b0082d6998f61e54c90c44b45cfb91a98ddb1bb3a857ecbbcffb0c28b2f758de2a2af24df7667020e316eed3f9cb26c527061a91364231b54ed8911faf94dd6fbbf0d4180e05adaebeea604bebd25cca810d812f47a7824aa96d93c4ad6a1ac0072ec39006b4';
        expect(res).toEqual(expected);
    });
    test('calculates x', () => {
        const auth = new Authenticator(USERNAME, PASSWORD, URL);
        const salt = new BigInteger('5828aedc', 16);
        const username = 'cctst0007';
        const password = 'aaaaaFFFFFF';

        const res = auth._calculate_x(username, password, salt);

        const expected = '9016c8630770256d5fe245b7f43957770f47e696';
        expect(res.toString(16)).toEqual(expected);
    });

    test('calculates u', () => {
        const auth = new Authenticator(USERNAME, PASSWORD, URL);
        const N = new BigInteger('d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43', 16);
        const A = new BigInteger('ce876a77d005e5facdec57672606278a2a3d3e06837c4e436e38cd6a300d3a5c02e6262536cc8b8f44c52a0752f2e6815819a5d45f31bd3650a6b27a4c500dea', 16);
        const B = new BigInteger('b5cefbd62e05152729f19677250ad00fc8e70423d3a7ada00d1a4da49da639ab053ab203210f61fb825f7c141553063f4c16d5cf148518ab7308ba034db4d3ff', 16);

        const res = auth._calculate_u(N, A, B);

        const expected = 'd71c61b35bb69c66d5f46441c471063a4047b6e8';
        expect(res.toString(16)).toEqual(expected);
    });

    test('calculates client secret', () => {
        const auth = new Authenticator(USERNAME, PASSWORD, URL);
        const g = new BigInteger('2', 16);
        const N = new BigInteger('d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43', 16);
        const B = new BigInteger('b5cefbd62e05152729f19677250ad00fc8e70423d3a7ada00d1a4da49da639ab053ab203210f61fb825f7c141553063f4c16d5cf148518ab7308ba034db4d3ff', 16);
        const x = new BigInteger('8118b6a647a8f13465dcbce590b8ad7d1a1a9e32', 16);
        const u = new BigInteger('d71c61b35bb69c66d5f46441c471063a4047b6e8', 16);
        const a = new BigInteger('4e7533a976f6b75ff6747480348531329bfe1a51db13eb88a667f93d45ca4333', 16);
        const k = new BigInteger('3', 16);

        const res = auth._calculate_client_secret(g, N, B, x, u, a, k);

        const expected = '4605796a7d184b567e571324c4fd9b249b4ddf6aa86cbdef78715b99b24857ff4fbfe631f918fca38e08cb0dd996b61baeddb9bad7ae2c1bc15aa218c6e1c335';
        expect(res.toString(16)).toEqual(expected);
    });

    test('calculates K', () => {
        const auth = new Authenticator(USERNAME, PASSWORD, URL);
        const secret = new BigInteger('4605796a7d184b567e571324c4fd9b249b4ddf6aa86cbdef78715b99b24857ff4fbfe631f918fca38e08cb0dd996b61baeddb9bad7ae2c1bc15aa218c6e1c335', 16);

        const res = auth._calculate_K(secret);

        const expected = '8a6597a8252bb111aac98db40e1a0592d6e02bbd';
        expect(res).toEqual(expected);
    });

    test('calculates M', () => {
        const auth = new Authenticator(USERNAME, PASSWORD, URL);
        const g = new BigInteger('2', 16);
        const N = new BigInteger('d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43', 16);
        const username = 'cctst0007';
        const salt = new BigInteger('5828aedc', 16);
        const A = new BigInteger('1c3f80071a176b2e6ccd09a0beb6607cd4b30b76e3db70497c2b545fc697f8df4811b2770bee8307221de3d54496c7607932fa4499f83dbbec120895580c4bdf', 16);
        const B = new BigInteger('1ef19465b5bc1f2df568189e5b6e6435f67701ea1b6e1a567d1d89171369602456c50272c55687ff0bf25c16c4d196afc66cf92232ca6978804e9af15e0c1cf0', 16);
        const K = new BigInteger('b4ca9cf34d2f71c69251fe1885ca0f5243e44425', 16);

        const res = auth._calculate_M(N, g, username, salt, A, B, K);

        const expected = '45c39cfbb824a19c99f5a5b4fee88a56c3221efe';
        expect(res).toEqual(expected);
    });

    test('calculates M2', () => {
        const auth = new Authenticator(USERNAME, PASSWORD, URL);
        const A = '9a28e06d1920814294dc068546da20a0575368f4995b64624a847b0168259ab2f1bf7fff2a42fe7eb32fb9aadba203a7a25ee39dbbdd2085c19c1865665e39f1';
        const M = '0addd3c5fe5dba94e721d65080262a514347dd9f';
        const K = 'f7406e754f1eec3d8cfcad8eda30e2940a8cefb6';

        const res = auth._calculate_M2(A, M, K);

        const expected = '7f8aec26e74b752b9eae391aeee8f77d34428ccc';
        expect(res).toEqual(expected);
    });
});
