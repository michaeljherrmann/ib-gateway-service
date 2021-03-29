const twilio = require('twilio');


class Sms {
    static async getChallenge(authStartedAt) {
        const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
        const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
        const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

        let err;
        for (let i = 0; i <= 5; i++) {
            console.log(`Checking for auth SMS in ${i}s`)
            await new Promise(resolve => setTimeout(resolve, i * 1000));
            try {
                return await Sms._getCode(client, authStartedAt);
            } catch (e) {
                err = e;
            }
        }

        // could not complete two factor after retries
        throw new Error(`Two factor authentication could not complete in time due to ${err}`);
    }

    static async _getCode(client, authStartedAt) {
        const messages = await client.messages.list({
            dateSentAfter: authStartedAt,
            limit: 1,
        });
        if (messages.length !== 1) {
            throw new Error(`Twilio returned ${messages.length} messages`);
        }
        const message = messages[0];
        console.log('Retrieved message from twilio');
        const match = message.body.match(/\d{6}/);
        if (match === null) {
            throw new Error(`Could not extract code from message body: "${message.body}"`)
        }
        return match[0];
    }
}

module.exports = Sms;
