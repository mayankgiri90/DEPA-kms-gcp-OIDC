#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

akv-key-create() {
    set -e
    set -x

    AKV_VAULT_NAME=${AKV_VAULT_NAME:-$1}
    if [ -z "$AKV_VAULT_NAME" ]; then
        read -p "Enter AKV name: " AKV_VAULT_NAME
    fi
    export AKV_VAULT_NAME

    # Create a workspace for certs
    export WORKSPACE=~/$DEPLOYMENT_NAME.aclworkspace
    mkdir -p $WORKSPACE/proposals

    export MEMBER_CERT_NAME=${DEPLOYMENT_NAME}-member0
    export USER_CERT_NAME=${DEPLOYMENT_NAME}-user0
    export KMS_WORKSPACE=${WORKSPACE}
    export KMS_MEMBER_CERT_PATH=${KMS_WORKSPACE}/member0_cert.pem
    export KMS_USER_CERT_PATH=${KMS_WORKSPACE}/user0_cert.pem

    az keyvault certificate create \
        --vault-name $AKV_VAULT_NAME \
        --name $MEMBER_CERT_NAME \
        --policy @./scripts/akv/key_policy.json

    az keyvault certificate create \
        --vault-name $AKV_VAULT_NAME \
        --name $USER_CERT_NAME \
        --policy @./scripts/akv/key_policy.json

    # Downloads the member certificate
    az keyvault certificate download \
        --file ${KMS_MEMBER_CERT_PATH} \
        --vault-name $AKV_VAULT_NAME \
        --name $MEMBER_CERT_NAME

    # Downloads the user certificate
    az keyvault certificate download \
        --file ${KMS_USER_CERT_PATH} \
        --vault-name $AKV_VAULT_NAME \
        --name $USER_CERT_NAME

    set +e
}

akv-key-create "$@"

jq -n '{
    KMS_WORKSPACE: env.KMS_WORKSPACE,
    KMS_MEMBER_CERT_PATH: env.KMS_MEMBER_CERT_PATH,
    KMS_USER_CERT_PATH: env.KMS_USER_CERT_PATH,
    MEMBER_CERT_NAME: env.MEMBER_CERT_NAME,
    USER_CERT_NAME: env.USER_CERT_NAME
}'
