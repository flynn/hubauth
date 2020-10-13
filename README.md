# hubauth

Hubauth is a service that provides Single Sign-On for Flynn clusters. It operates as an OAuth 2.0 server that the Flynn CLI and Dashboard interact with, and issues signed tokens that the Flynn controller consumes.

Users are authenticated using G Suite via OpenID Connect, and their group membership is checked to determine which clusters (audiences) they have access to.

The service is deployed on Google Cloud Run, and uses Firestore in Datastore mode as the database.

Cloud Key Management Service is used to store signing keys.

## Testing

The test environment can be built in Docker by running:

```
docker build -t hubauth-test -f test.Dockerfile .
```

The tests can be run with:

```
docker run --rm -v `pwd`:/app hubauth-test
```

## Deployment in testing

Create docker tag for gcr.io and push the image:

```
docker build -t us.gcr.io/<PROJECT_ID>/hubauth-dev:latest -f build.Dockerfile .
docker push us.gcr.io/<PROJECT_ID/hubauth-dev:latest

# if not authorized, you may need to run `gcloud auth configure-docker`
```

### In Security > Cryptographic Keys

Create a KMS keyring: 
- name: `hubauth-keyring`
- location: `global`
Create a KMS key: 
- name: `refresh_key`
- type: `software Asymmetric sign key`

And save its `version 1` resource name

In Security > Secret manager:
Create secrets 
- `HUBAUTH_COOKIE_KEY_SECRET`: secure random value
- `HUBAUTH_CODE_KEY_SECRET`: secure random value

And save their resource IDs

### In IAM

Grant default compute account the roles:
- Cloud KMS CryptoKey Signer/Verifier
- Cloud Trace Agent
- Cloud Datastore User
- Errors Writer
- Service Account Token Creator
- Monitoring Metric Writer
- Cloud Run Invoker
- Secret Manager Secret Accessor

### In Cloud Run

Create service:
- Name: `hubauth-ext`
- Allows unauthenticated invocations
- Select the previously pushed docker image

Then edit & deploy new revision:
- Container command: `/app/hubauth-ext`
- Variables:
  - PROJECT_ID: current GCP project id
  - REFRESH_KEY: set it to the KMS refresh_key resource name saved previously
  - COOKIE_KEY_SECRET: set to the resource ID from `HUBAUTH_COOKIE_KEY_SECRET`
  - CODE_KEY_SECRET: set to the resource ID from `HUBAUTH_CODE_KEY_SECRET`
  - KMS_LOCATION: `global`
  - KMS_KEYRING: `hubauth-keyring`

And save the deployment URL

Create service:
- Name: `hubauth-int`
- Allows unauthenticated invocations
- Select the previously pushed docker image

Then edit & deploy new revision:
- Container command: `/app/hubauth-int`
- Variables:
  - PROJECT_ID: current GCP project id

And save the deployment URL

### In APIs & Services

Enable the APIs:
- Cloud Run Admin API
- Cloud Trace API	
- Secret Manager API
- Cloud Key Management Service (KMS) API
- IAM Service Account Credentials API
- Cloud Scheduler API
- Admin SDK
- Cloud Functions API

Create OAUTH Consent screen:
- Application type: `internal`
- Application name: `hubauth`
- Authorized domains: add the cloud run url for hubauth-ext

Create OAUTH Credential:
- Type: `web application`
- Name: `hubauth`
- Authorized url: add the cloud run url for hubauth-ext: `<URL>/rp/google`

Save `Client ID` and `Client secret`

### In Cloud RUN

Create a new deployment for `hubauth-ext`, and set the following variables:
- BASE_URL: add the cloud run url for hubauth-ext
- RP_GOOGLE_CLIENT_ID: the previously saved `Client ID`
- RP_GOOGLE_CLIENT_SECRET: the previously saved `Client secret`


### In Cloud Scheduler

Create a new job:
- Name: `hubauth-cron`
- Frequency: `0 */1 * * *`
- URL: use the hubauth-int URL: `<URL>/cron`


## Enabling Biscuit

To use biscuit tokens instead of bearers, configure the following:

### In Security > Secret manager

Create new secret 
- HUBAUTH_BISCUIT_ROOT_PRIVKEY: a base64 encoded p256 EC private key

### In variables

Add a new variable
- TOKEN_TYPE: `Biscuit`
- BISCUIT_ROOT_PRIVKEY:  set to the resource ID from `HUBAUTH_BISCUIT_ROOT_PRIVKEY`


## Hubauth CLI

Configure gcloud auth application-default with the following command, and follow the browser instructions:

```
gcloud auth application-default login
```

You'll need to create a client, and audience and ask an admin for setting up the policy (it requires allowing your app and user on org level, and allow the compute service account oauth ClientID on GSuite domain).

### Example commands

```
# create client
go run cmd/hubauth/main.go --project-id="<PROJECT_ID>" clients create \
    --redirect-uris http://localhost \
    --refresh-token-expiry 3600

# list clients
go run cmd/hubauth/main.go --project-id="<PROJECT_ID>" clients list

# create audience
go run cmd/hubauth/main.go --project-id="<PROJECT_ID>" audiences create \
    --audience-url https://localhost \
    --client-ids EhEKBkNsaWVudBCAgIDo14eBCg \
    --kms-location global \
    --kms-keyring hubauth

# list audiences
go run cmd/hubauth/main.go --project-id="<PROJECT_ID>" audiences list

# set audience policy
go run cmd/hubauth/main.go --project-id="<PROJECT_ID>" audiences set-policy \
    --audience-url https://localhost \
    --domain domain.io \
    --api-user user@domain.io \
    --groups group1,group2

go run cmd/hubauth/main.go --project-id="<PROJECT_ID>" audiences key \
    --audience-url https://localhost \
    --kms-location global \
    --kms-keyring hubauth
```
