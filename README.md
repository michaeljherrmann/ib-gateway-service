# ib-gateway-service
A light-weight node server to programatically control the [IBKR Client Portal Web gateway](https://interactivebrokers.github.io/cpwebapi/).
This service supports automatic authentication, including two factor with with IBKey or SMS.

Under the hood, this does not use any sort of android emulator nor browser, *everything*
 (including two factor) is done via http requests.

# Getting started
#### Fetch the docker image:
 ```
 docker pull mjherrma/ib-gateway-service:3.0.0
```
#### Start the service:
```
docker run -p 5050:5050 -p 5000:5000 mjherrma/ib-gateway-service:3.0.0
```
#### Start Client Portal (CP) gateway:
```
curl -X POST http://localhost:5050/api/service
```
#### Authenticate CP gateway (assuming no 2nd factor required):
```
curl -X PUT -d "username=USERNAME&password=PASSWORD" http://localhost:5050/api/service
```
Now the CP gateway is ready to go: `curl -k https://localhost:5000/v1/portal/iserver/auth/status`

#### Stop CP gateway:
```
curl -X DELETE http://localhost:5050/api/service
```

## Environment variables:

| Name  | Default Value | Description |
| ------------- | ------------- | ------------- |
| IB_GATEWAY_SERVICE_PORT  | 5050  | Port on which this service listens  |
| IB_GATEWAY_DATA_STORE_PATH  | /tmp/ib_gateway_data/  | Required for IBKey, where the service can write persistent data  |
| IB_AUTH_OCRA_SECRET  | *null*  | Required for IBKey, output from setup-ibkey script  |
| IB_AUTH_OCRA_PIN  | *null*  | Required for IBKey, pin entered during setup-ibkey  |
| IB_AUTH_TWILIO_ACCOUNT_SID  | *null*  | Required for SMS two factor, twilio account SID  |
| IB_AUTH_TWILIO_AUTH_TOKEN  | *null*  | Required for SMS two factor, twilio auth token  |
| IB_AUTH_MAX_ATTEMPTS  | 2  | Max failed login attempts before disabling login (to prevent accidentally locking IB account)  |

# Authentication
## Two Factor Authentication
IB Gateway Service is setup to use [twilio](https://www.twilio.com) for SMS two factor
. Register your IB account with a twilio phone number and then provide the IB Gateway Service
 with the twilio account SID and auth token via environment variables.
 
 Note that IB does not allow you to change your second factor phone number after creating an
  account. If you already have a personal phone number connected, a way around this is to use an SMS
   forwarding app on your phone to automatically forward the IB SMS messages to the twilio phone
    number. Or set up [IBKey](#ibkey-authentication)!
    
## IBKey Authentication
In order to set up IBKey, you need to run the IBKey setup script:
```
docker run -it mjherrma/ib-gateway-service:3.0.0 bash -c 'npm run setup-ibkey'
```
If successful, the script will output the IBKey secret. This needs to be passed into the environment
 variable: `IB_AUTH_OCRA_SECRET` and the pin created during setup also needs to be provided via
  `IB_AUTH_OCRA_PIN`
  
**Important:** the path to `IB_GATEWAY_DATA_STORE_PATH` must persist as long as you want to keep
 using IBKey login without setting it up again. Each login attempt increments a counter, which is
  stored at that data path.

## Max attempts
In order to prevent accidentally locking the IB account, this service will stop attempting to
 login after `IB_AUTH_MAX_ATTEMPTS` consecutive failed attempts. If this happens, it requires
  manual reset by writing '0' to `attempt.txt` (located at `IB_GATEWAY_DATA_STORE_PATH`) or
   simply deleting that file works too.
