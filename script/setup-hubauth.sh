#!/usr/bin/env bash

set -ueo pipefail

KMS_LOCATION=${KMS_LOCATION-"global"}
KMS_KEYRING=${KMS_KEYRING-"hubauth"}
TOKEN_TYPE=${TOKEN_TYPE-"Bearer"} # || Biscuit
PROJECT_ID=${PROJECT_ID-""}

EXPECTED_HUBAUTH_EXT_ENV=(
    # env provided or script default
    "KMS_LOCATION"
    "KMS_KEYRING"
    "TOKEN_TYPE"
     # env provided or auto populated using gcloud 
    "PROJECT_ID"
    # auto populated using gcloud 
    "BASE_URL"
    # auto generated kms key if not existing
    "REFRESH_KEY"
    # auto generated secrets if not existing
    "COOKIE_KEY_SECRET"
    "CODE_KEY_SECRET"
    "BISCUIT_ROOT_PRIVKEY" # only when TOKEN_TYPE == "Biscuit"
    # need user input
    "RP_GOOGLE_CLIENT_ID"
    "RP_GOOGLE_CLIENT_SECRET"
)

EXPECTED_HUBAUTH_INT_ENV=(
    # env provided or auto populated using gcloud 
    "PROJECT_ID"
)


case "${TOKEN_TYPE}" in
"Bearer" | "Biscuit")
    ;;
*)
    echo "invalid TOKEN_TYPE \"${TOKEN_TYPE}\", must be either \"Bearer\" or \"Biscuit\""
    exit 1
    ;;
esac

if [ $# -lt 2 ] || [[ " $@ " =~ "-h" ]] || [[ " $@ " =~ "--help" ]]; then 
    echo "Wizard to check and configure hubauth services and their GCP dependencies" 
	echo -e "\nUsage:\n$0 <APP> <REGION> [-h|--help]\n" 
    echo -e "\nARGUMENTS:"
    echo -e "\tAPP:         the application to configure (\"hubauth-int\" or \"hubauth-ext\")"
    echo -e "\tREGION:      a GCP region where the application exists (ie: \"us-central1\")"
    echo -e "\t-h | --help: print this help"
    echo -e "\nENV:"
    echo -e "\tPROJECT_ID   (default to current gcloud active config project)"
    echo -e "\t             Prompt for confirmation when not specified"
    echo -e "\tKMS_LOCATION (default to \"${KMS_LOCATION}\")"
    echo -e "\tKMS_KEYRING  (default to \"${KMS_KEYRING}\")"
    echo -e "\tTOKEN_TYPE   (default to \"${TOKEN_TYPE}\", accept \"Bearer\" or \"Biscuit\")\n"
    exit 1
fi

APP=$1
REGION=$2

if [ -z "${PROJECT_ID}" ]; then
    PROJECT_ID=$(gcloud config get-value project)
    read -p "Current project: ${PROJECT_ID}, confirm ? [Yn]: " 
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "operation cancelled"
        exit 0
    fi
fi

GCLOUD="gcloud --project ${PROJECT_ID}"

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


SPECS=$(${GCLOUD} run services describe "${APP}-${REGION}" --platform managed --region "${REGION}" --format json)

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
        value=${PROJECT_ID}
        ;;
    "BASE_URL")
        value=$(echo "${SPECS}" | jq -r '.status.url // empty')
        ;;
    "COOKIE_KEY_SECRET" | "CODE_KEY_SECRET")
        value=$(${GCLOUD} secrets describe "${env}" --format 'value("name")' || true)
        if [ -z "${value}" ]; then
            head -c 32 /dev/random | base64 -w0 | ${GCLOUD} secrets create ${env} --data-file -
            value=$(${GCLOUD} secrets describe "${env}" --format 'value("name")')
        fi
        value+="/versions/latest"
        ;;
    "BISCUIT_ROOT_PRIVKEY")
        if [ "${TOKEN_TYPE}" != "Biscuit" ]; then
            continue
        fi
        value=$(${GCLOUD} secrets describe "${env}" --format 'value("name")' || true)
        if [ -z "${value}" ]; then
            head -c 32 /dev/random | base64 -w0 | ${GCLOUD} secrets create ${env} --data-file -
            value=$(${GCLOUD} secrets describe "${env}" --format 'value("name")')
        fi
        value+="/versions/latest"
        ;;
    "REFRESH_KEY")
        value=$(${GCLOUD} kms keys versions list --key "${env}" --keyring "${KMS_KEYRING}" --location "${KMS_LOCATION}" --format 'value("name")' 2>/dev/null | sort -r | head -n1 || true)
        if [ -z "${value}" ]; then
            ${GCLOUD} kms keys create "${env}" \
                --keyring "${KMS_KEYRING}" \
                --location "${KMS_LOCATION}" \
                --purpose "asymmetric-signing" \
                --default-algorithm "ec-sign-p256-sha256" \
                --protection-level "software"
            value=$(${GCLOUD} kms keys versions list --key "${env}" --keyring "${KMS_KEYRING}" --location "${KMS_LOCATION}" --format 'value("name")')
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
    ${GCLOUD} run deploy "${APP}-${REGION}" --platform managed --region "${REGION}" --image "${IMAGE}" --update-env-vars "${ENV_STR}"
fi

BASE_URL=$(${GCLOUD} run services describe "${APP}-${REGION}" --platform managed --region "${REGION}" --format json | jq -r '.status.url')

# we need a first successful deployment in order to obtain the service URL. 
# so when it was empty, and the above deploy succeeded, we can immediatly redeploy setting the BASE_URL env
if [ -z "$(echo ${SPECS} | jq -r '.status.url // empty')" ] && [[ "${EXPECTED_APP_ENV[@]}" =~ "BASE_URL" ]]; then
    echo "just obtained a service url for the first time, setting BASE_URL env variable..."
    ${GCLOUD} run deploy "${APP}-${REGION}" --platform managed --region "${REGION}" --image "${IMAGE}" --update-env-vars "BASE_URL=${BASE_URL}"
fi

# Create a scheduler invoking hubauth-int /cron endpoint
# Using below service account for authentication (or create it if needed)
SA_NAME="scheduler-runner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if [ ${APP} = "hubauth-int" ] && [ ! -z ${BASE_URL} ]; then
    if [ -z "$(${GCLOUD} scheduler jobs describe "${APP}-${REGION}-CRON" 2>/dev/null || true)" ]; then
        if [ -z "$(${GCLOUD} iam service-accounts describe "${SA_EMAIL}" 2>/dev/null || true)" ]; then
            ${GCLOUD} iam service-accounts create "${SA_NAME}" --display-name="GCloud Scheduler SA"
            ${GCLOUD} projects add-iam-policy-binding --quiet "${PROJECT_ID}" --member "serviceAccount:${SA_EMAIL}" --role "roles/run.invoker"
        fi
        
        ${GCLOUD} scheduler jobs create http "${APP}-${REGION}-CRON" \
            --description "sync & cleanup task for hubauth" \
            --schedule "0 */1 * * *" \
            --uri "${BASE_URL}/cron" \
            --http-method "get" \
            --oidc-service-account-email "${SA_EMAIL}" \
            --oidc-token-audience "${BASE_URL}"
    fi
fi
