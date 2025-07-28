const crypto = require('crypto');

class Sha1 {
    static hashFromHex(input) {
        const buffer = Buffer.from(input, 'hex');
        return Sha1.hash(buffer);
    }

    static hash(...input) {
        const shasum = crypto.createHash('sha1');
        input.forEach(i => shasum.update(i));
        return shasum.digest('hex');
    }

}

module.exports = Sha1;
