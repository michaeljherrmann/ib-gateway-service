
class TwoFactorError extends Error {
    constructor(message) {
        super(message);
        this.name = "TwoFactorError";
    }
}


module.exports = {
    TwoFactorError,
}
