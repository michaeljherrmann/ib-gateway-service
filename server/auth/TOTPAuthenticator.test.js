const { authenticator } = require('otplib');

describe('TOTPAuthenticator', () => {
    describe('TOTP generation and verification', () => {
        test('generates valid TOTP code from secret', () => {
            const secret = 'JBSWY3DPEHPK3PXP';
            const token = authenticator.generate(secret);

            // Token should be 6 digits
            expect(token).toMatch(/^\d{6}$/);
        });

        test('verifies correct TOTP code', () => {
            const secret = 'JBSWY3DPEHPK3PXP';
            const token = authenticator.generate(secret);

            const isValid = authenticator.verify({ token, secret });
            expect(isValid).toBe(true);
        });

        test('rejects invalid TOTP code', () => {
            const secret = 'JBSWY3DPEHPK3PXP';
            const invalidToken = '000000';

            const isValid = authenticator.verify({ token: invalidToken, secret });
            expect(isValid).toBe(false);
        });

        test('generates different codes at different times', () => {
            // This test uses a fixed time to ensure deterministic results
            const secret = 'JBSWY3DPEHPK3PXP';

            // Generate token at time 1
            const time1 = 1622505600; // 2021-06-01 00:00:00 UTC
            const token1 = authenticator.generate(secret);
            authenticator.options = { epoch: time1 * 1000 };
            const tokenAtTime1 = authenticator.generate(secret);

            // Generate token at time 2 (31 seconds later, should be different)
            const time2 = time1 + 31; // More than 30 seconds later
            authenticator.options = { epoch: time2 * 1000 };
            const tokenAtTime2 = authenticator.generate(secret);

            // Tokens should be different because time window changed
            expect(tokenAtTime1).not.toBe(tokenAtTime2);
        });

        test('secret generation creates valid base32 secret', () => {
            const secret = authenticator.generateSecret();

            // Should be a non-empty string
            expect(secret).toBeTruthy();
            expect(typeof secret).toBe('string');

            // Should be valid base32 (uppercase A-Z and 2-7)
            expect(secret).toMatch(/^[A-Z2-7]+$/);

            // Should be able to generate a token from it
            const token = authenticator.generate(secret);
            expect(token).toMatch(/^\d{6}$/);
        });

        test('verifies token within time window', () => {
            const secret = 'JBSWY3DPEHPK3PXP';

            // Generate a token
            const token = authenticator.generate(secret);

            // Should be valid immediately
            expect(authenticator.verify({ token, secret })).toBe(true);

            // Should still be valid with a small time window
            // (within same 30-second window)
            expect(authenticator.check(token, secret)).toBe(true);
        });
    });

    describe('TOTP configuration', () => {
        test('default generates exactly 6 digits', () => {
            const secret = 'JBSWY3DPEHPK3PXP';
            const token = authenticator.generate(secret);

            // Must be exactly 6 digits
            expect(token).toHaveLength(6);
            expect(token).toMatch(/^\d{6}$/);
            expect(parseInt(token)).toBeGreaterThanOrEqual(0);
            expect(parseInt(token)).toBeLessThanOrEqual(999999);
        });

        test('generates token with custom step (time window)', () => {
            const secret = 'JBSWY3DPEHPK3PXP';

            // Configure for 60-second window instead of default 30
            authenticator.options = { step: 60 };
            const token = authenticator.generate(secret);

            expect(token).toMatch(/^\d{6}$/);

            // Reset to defaults
            authenticator.resetOptions();
        });

        test('generates token with custom digits', () => {
            const secret = 'JBSWY3DPEHPK3PXP';

            // Configure for 8-digit code
            authenticator.options = { digits: 8 };
            const token = authenticator.generate(secret);

            expect(token).toMatch(/^\d{8}$/);

            // Reset to defaults
            authenticator.resetOptions();
        });
    });

    describe('keyuri generation for QR codes', () => {
        test('generates proper keyuri for Google Authenticator', () => {
            const secret = 'JBSWY3DPEHPK3PXP';
            const user = 'testuser';
            const service = 'IB Gateway';

            const keyuri = authenticator.keyuri(user, service, secret);

            expect(keyuri).toContain('otpauth://totp/');
            expect(keyuri).toContain(encodeURIComponent(service));
            expect(keyuri).toContain(user);
            expect(keyuri).toContain(secret);
        });
    });
});
