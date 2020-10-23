#!/usr/bin/env bash

set -ueo pipefail

APP="hubauth-ext"
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


if [ $# -lt 1 ]; then 
    echo "Wizard to check and help configuring hubauth-ext service" 
	echo -e "\nUsage:\n$0 [REGION] \n" 
    exit 1
fi

REGION=$1

SPECS=$(gcloud run services describe "${APP}-${REGION}" --platform managed --region "${REGION}" --format json)

CONTAINER_SPECS=$(echo "${SPECS}" | jq '.spec.template.spec.containers[0]')
IMAGE=$(echo "${CONTAINER_SPECS}" | jq -r '.image')

NEW_ENVS=()
for env in ${EXPECTED_HUBAUTH_EXT_ENV[@]}; do
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
    "COOKIE_KEY_SECRET" | "CODE_KEY_SECRET" | "BISCUIT_ROOT_PRIVKEY")
        if [ "${env}" = "BISCUIT_ROOT_PRIVKEY" ] && [ "${TOKEN_TYPE}" != "Biscuit" ]; then
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


# we need a first successful deployment in order to obtain the service URL. 
# so when it was empty, and the above deploy succeeded, we can immediatly redeploy setting the BASE_URL env
if [ -z "$(echo ${SPECS} | jq -r '.status.url // empty')" ]; then
    echo "just obtained a service url for the first time, setting BASE_URL env variable..."
    BASE_URL=$(gcloud run services describe "${APP}-${REGION}" --platform managed --region "${REGION}" --format json | jq -r '.status.url')
    gcloud run deploy "${APP}-${REGION}" --platform managed --region "${REGION}" --image "${IMAGE}" --update-env-vars "BASE_URL=${BASE_URL}"
fi
