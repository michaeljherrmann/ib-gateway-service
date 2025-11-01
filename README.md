# ib-gateway-service
A light-weight node server to programatically control the [IBKR Client Portal Web gateway](https://interactivebrokers.github.io/cpwebapi/).
This service supports automatic authentication, including two-factor authentication with TOTP (Google Authenticator, Authy, etc.).

Under the hood, this does not use any sort of android emulator nor browser, *everything*
 (including two factor) is done via http requests.

# Getting started
#### Fetch the docker image:
 ```
 docker pull mjherrma/ib-gateway-service:3.0.3
```
#### Start the service:
```
docker run -p 5050:5050 -p 5000:5000 mjherrma/ib-gateway-service:3.0.3
```
#### Start Client Portal (CP) gateway:
```
curl -X POST http://localhost:5050/api/service
```
#### Authenticate CP gateway with TOTP (recommended):
```
curl -X PUT -H "Content-Type: application/json" \
  -d '{"username":"USERNAME","password":"PASSWORD","totpSecret":"YOUR_TOTP_SECRET"}' \
  http://localhost:5050/api/service
```

#### Or authenticate without 2nd factor:
```
curl -X PUT -d "username=USERNAME&password=PASSWORD" http://localhost:5050/api/service
```
Now the CP gateway is ready to go: `curl -k https://localhost:5000/v1/portal/iserver/auth/status`

#### Stop CP gateway:
```
curl -X DELETE http://localhost:5050/api/service
```

## Environment variables:

| Name  | Default Value         | Description                                                                                   |
| ------------- |-----------------------|-----------------------------------------------------------------------------------------------|
| IB_GATEWAY_SERVICE_PORT  | 5050                  | Port on which this service listens                                                            |
| IB_AUTH_MAX_ATTEMPTS  | 4                     | Max failed login attempts before disabling login (to prevent accidentally locking IB account) |
| IB_GATEWAY_DATA_STORE_PATH  | /tmp/ib_gateway_data/ | Where the service can write persistent data                                                   |

# Authentication
This service enables a truly headless login to the IB gateway, including two-factor authentication.

## TOTP Authentication (Recommended)
The easiest and most reliable way to authenticate is using TOTP (Time-based One-Time Password) with apps like Google Authenticator, Authy, Microsoft Authenticator, or any other RFC 6238-compliant authenticator app.

### Setup:
1. Configure your Interactive Brokers account to use an authenticator app for two-factor authentication
2. When setting up the authenticator, save the secret key (usually shown as a QR code and a text string in base32 format)
3. Pass the TOTP secret along with your credentials when authenticating:

```bash
curl -X PUT -H "Content-Type: application/json" \
  -d '{"username":"YOUR_USERNAME","password":"YOUR_PASSWORD","totpSecret":"JBSWY3DPEHPK3PXP"}' \
  http://localhost:5050/api/service
```

That's it! The service will automatically generate the correct 6-digit codes during login. The TOTP secret is passed securely through the API request body and is not persisted by the service.

## Max Login Attempts
In order to prevent accidentally locking your IB account, this service will stop attempting to
 login after `IB_AUTH_MAX_ATTEMPTS` consecutive failed attempts. If this happens, it requires
  manual reset by updating the attempts value in `${IB_GATEWAY_DATA_STORE_PATH}/data.json` to `0`.

---

# Deprecated Authentication Methods

The following authentication methods are still supported but are no longer recommended. TOTP authentication (above) is simpler and more reliable.

<details>
<summary>Click to expand deprecated methods (SMS via Twilio & IBKey)</summary>

## SMS Authentication via Twilio (Deprecated)
```bash
IB_AUTH_TWILIO_ACCOUNT_SID=XXXXXXXXXXXXX # must be set
IB_AUTH_TWILIO_AUTH_TOKEN=XXXXXXXXXXXXX # must be set
```

IB Gateway Service can use [twilio](https://www.twilio.com) for SMS two factor.
Register your IB account with a twilio phone number and then provide the IB Gateway Service
 with the twilio account SID and auth token via environment variables.

I recommend [adding another user](https://www.ibkrguides.com/orgportal/uar/addingauser.htm) to your IBKR account, which you will use for API login.
When creating this user, you have options to limit permissions (likely you'll want to share market data and trading permissions) and set the phone number.
Be sure you use your twilio phone number here—this way you can receive the two factor SMS programmatically.

Note that IB does not allow you to change your second factor phone number after creating an
account. If you already have a personal phone number connected, a way around this is to use an SMS
forwarding app on your phone to automatically forward the IB SMS messages to the twilio phone number.

### Environment Variables:
| Name  | Default Value | Description |
| ----- | ------------- | ----------- |
| IB_AUTH_TWILIO_ACCOUNT_SID | *null* | Twilio account SID |
| IB_AUTH_TWILIO_AUTH_TOKEN | *null* | Twilio auth token |

## IBKey Authentication (Deprecated)
```bash
IB_AUTH_USE_IBKEY=true
IB_GATEWAY_DATA_STORE_PATH=/auth/data/path # will be used
```
You can use the IBKey authentication method. This will require you to set up IBKey on your computer and then provide the secret to the service.

You will have to repeat this process at least every 100 logins (`IB_AUTH_MAX_COUNTER`), but between those logins, the service
will automatically be able to login with two factor.

In order to set up IBKey, you need to run the IBKey setup script:
```bash
docker run -it mjherrma/ib-gateway-service:3.0.3 bash -c 'npm run setup-ibkey'
```
If successful, the script will output the IBKey auth data. This must be saved as a json file
named `data.json` and placed in `IB_GATEWAY_DATA_STORE_PATH`

**Important:** the path to `IB_GATEWAY_DATA_STORE_PATH` must persist as long as you want to keep
 using IBKey login without setting it up again. Each login attempt increments a counter, which is
  stored at that data path.

### Environment Variables:
| Name  | Default Value | Description |
| ----- | ------------- | ----------- |
| IB_AUTH_USE_IBKEY | *false* | Use IBKey for two factor |
| IB_AUTH_MAX_COUNTER | 95 | The number of logins before IBKey will be reinitialized. Max 100 |

## Using SMS + IBKey Together (Deprecated)
```bash
IB_AUTH_USE_IBKEY=true
IB_AUTH_TWILIO_ACCOUNT_SID=XXXXXXXXXXXXX # must be set
IB_AUTH_TWILIO_AUTH_TOKEN=XXXXXXXXXXXXX # must be set
IB_GATEWAY_DATA_STORE_PATH=/auth/data/path # will be used
```
You can use both methods at the same time. The only real advantage to this is to reduce the number of
twilio SMS messages (by up to 100x). Since IBKey will only need to reset once per 100 logins using
SMS authentication.

</details>
