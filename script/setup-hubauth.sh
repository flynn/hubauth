#!/usr/bin/env bash

set -ueo pipefail

KMS_LOCATION="global"
KMS_KEYRING="hubauth"
TOKEN_TYPE="Bearer" # || Biscuit

EXPECTED_HUBAUTH_EXT_ENV=(
    # provided by script variables
    "KMS_LOCATION"
    "KMS_KEYRING"
    "TOKEN_TYPE"
    # auto populated using gcloud 
    "PROJECT_ID"
    "BASE_URL"
    # auto generated kms key if not existing
    "REFRESH_KEY"
    # auto generated secrets if not existing
    "COOKIE_KEY_SECRET"
    "CODE_KEY_SECRET"
    "BISCUIT_ROOT_PRIVKEY" # only for "Biscuit" token type
    # need user input
    "RP_GOOGLE_CLIENT_ID"
    "RP_GOOGLE_CLIENT_SECRET"
)

EXPECTED_HUBAUTH_INT_ENV=(
    # auto populated using gcloud 
    "PROJECT_ID"
)

if [ $# -lt 2 ]; then 
    echo "Wizard to check and help configuring hubauth-ext service" 
	echo -e "\nUsage:\n$0 [hubauth-ext | hubauth-int] [REGION] \n" 
    exit 1
fi

APP=$1
REGION=$2

case "${APP}" in
"hubauth-ext")
    EXPECTED_APP_ENV=${EXPECTED_HUBAUTH_EXT_ENV[@]}
    ;;
"hubauth-int")
    EXPECTED_APP_ENV=${EXPECTED_HUBAUTH_INT_ENV[@]}
    ;;
*)
    echo "invalid app, it must be either hubauth-ext or hubauth-int"
    exit 1
    ;;
esac

SPECS=$(gcloud run services describe "${APP}-${REGION}" --platform managed --region "${REGION}" --format json)

CONTAINER_SPECS=$(echo "${SPECS}" | jq '.spec.template.spec.containers[0]')
IMAGE=$(echo "${CONTAINER_SPECS}" | jq -r '.image')

NEW_ENVS=()
for env in ${EXPECTED_APP_ENV[@]}; do
    EXISTS=$(echo "${CONTAINER_SPECS}" | jq '.env[] | . | select(.name | contains('\"${env}\"'))')
    if [ ! -z "${EXISTS}" ]; then
        continue
    fi
    
    case "${env}" in
    "KMS_LOCATION")
        value="${KMS_LOCATION}"
        ;;
    "KMS_KEYRING")
        value="${KMS_KEYRING}"
        ;;
    "TOKEN_TYPE")
        value="${TOKEN_TYPE}"
        ;;
    "PROJECT_ID")
        value=$(gcloud config get-value project)
        ;;
    "BASE_URL")
        value=$(echo "${SPECS}" | jq -r '.status.url // empty')
        ;;
    "COOKIE_KEY_SECRET" | "CODE_KEY_SECRET")
        value=$(gcloud secrets describe "${env}" --format 'value("name")' || true)
        if [ -z "${value}" ]; then
            head -c 32 /dev/random | base64 -w0 | gcloud secrets create ${env} --data-file -
            value=$(gcloud secrets describe "${env}" --format 'value("name")')
        fi
        value+="/versions/latest"
        ;;
    "BISCUIT_ROOT_PRIVKEY")
        if [ "${TOKEN_TYPE}" != "Biscuit" ]; then
            continue
        fi
        value=$(gcloud secrets describe "${env}" --format 'value("name")' || true)
        if [ -z "${value}" ]; then
            head -c 32 /dev/random | base64 -w0 | gcloud secrets create ${env} --data-file -
            value=$(gcloud secrets describe "${env}" --format 'value("name")')
        fi
        value+="/versions/latest"
        ;;
    "REFRESH_KEY")
        value=$(gcloud kms keys versions list --key "${env}" --keyring "${KMS_KEYRING}" --location "${KMS_LOCATION}" --format 'value("name")' | sort -r | head -n1 || true)
        if [ -z "${value}" ]; then
            gcloud kms keys create "${env}" \
                --keyring "${KMS_KEYRING}" \
                --location "${KMS_LOCATION}" \
                --purpose "asymmetric-signing" \
                --default-algorithm "ec-sign-p256-sha256" \
                --protection-level "software"
            value=$(gcloud kms keys versions list --key "${env}" --keyring "${KMS_KEYRING}" --location "${KMS_LOCATION}" --format 'value("name")')
        fi
        ;;
    *) # default ask for user input
        echo -n "enter value for ${env}: "
        read value
        ;;
    esac

    if [ ! -z "${value}" ]; then
        NEW_ENVS+=("${env}=${value}")
    fi
done

if [ ${#NEW_ENVS[@]} -gt 0 ]; then
    ENV_STR=$(IFS=,; printf '%s' "${NEW_ENVS[*]}")
    #echo $ENV_STR
    gcloud run deploy "${APP}-${REGION}" --platform managed --region "${REGION}" --image "${IMAGE}" --update-env-vars "${ENV_STR}"
fi

BASE_URL=$(gcloud run services describe "${APP}-${REGION}" --platform managed --region "${REGION}" --format json | jq -r '.status.url')

# we need a first successful deployment in order to obtain the service URL. 
# so when it was empty, and the above deploy succeeded, we can immediatly redeploy setting the BASE_URL env
if [ -z "$(echo ${SPECS} | jq -r '.status.url // empty')" ] && [[ "${EXPECTED_APP_ENV[@]}" =~ "BASE_URL" ]]; then
    echo "just obtained a service url for the first time, setting BASE_URL env variable..."
    gcloud run deploy "${APP}-${REGION}" --platform managed --region "${REGION}" --image "${IMAGE}" --update-env-vars "BASE_URL=${BASE_URL}"
fi

if [ ${APP} = "hubauth-int" ] && [ ! -z ${BASE_URL} ]; then
    EXISTS=$(gcloud scheduler jobs describe "${APP}-${REGION}-CRON" || true)
    if [ -z ${EXISTS} ]
        gcloud scheduler jobs create http "${APP}-${REGION}-CRON" \
            --description "sync & cleanup task for hubauth" \
            --schedule "0 */1 * * *" \
            --uri "${BASE_URL}/cron" \
            --http-method "get" \
fi
