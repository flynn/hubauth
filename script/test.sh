#!/usr/bin/env bash

set -uexo pipefail

main() {
    export CLOUDSDK_CORE_PROJECT=test
    export DATASTORE_EMULATOR_HOST=localhost:8081
    start-stop-daemon --start --background --no-close --exec \
      /usr/bin/gcloud -- beta emulators datastore start --no-store-on-disk --consistency=1
    
    while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' $DATASTORE_EMULATOR_HOST)" != "200" ]]; do sleep 1; done

    go test -race -v ./...
}

stop() {
    start-stop-daemon --stop --exec /usr/bin/java
}

trap stop EXIT


main $@
