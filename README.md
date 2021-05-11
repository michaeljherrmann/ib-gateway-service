# ib-gateway-service
A node server to programmatically control the [IBKR Client Portal Web gateway](https://interactivebrokers.github.io/cpwebapi/).
This service supports automatic authentication, including two factor with SMS.


# Getting started
#### Fetch the docker image:
 ```
 docker pull mjherrma/ib-gateway-service:2.1.0
```
#### Start the service:
```
docker run -p 5050:5050 -p 5000:5000 mjherrma/ib-gateway-service:2.1.0
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
| IB_AUTH_TWILIO_ACCOUNT_SID  | *null*  | Required for SMS two factor, twilio account SID  |
| IB_AUTH_TWILIO_AUTH_TOKEN  | *null*  | Required for SMS two factor, twilio auth token  |

# Authentication
## Two Factor Authentication
IB Gateway Service is setup to use [twilio](https://www.twilio.com) for SMS two factor
. Register your IB account with a twilio phone number and then provide the IB Gateway Service
 with the twilio account SID and auth token via environment variables. The service will
  automatically poll the twilio api if SMS two factor is required.
 
 Note that IB does not allow you to change your second factor phone number after creating an
  account. If you already have a personal phone number connected, a way around this is to use an SMS
   forwarding app on your phone to automatically forward the IB SMS messages to the twilio phone
    number.
