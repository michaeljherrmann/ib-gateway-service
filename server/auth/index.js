const Authenticator = require('./Authenticator');
const IBKeyAuthenticator = require('./IBKeyAuthenticator');
const { TwoFactorError } = require('./errors');

module.exports = {
    Authenticator,
    IBKeyAuthenticator,
    TwoFactorError
};
