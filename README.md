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
