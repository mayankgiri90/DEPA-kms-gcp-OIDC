#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

akv-key-import() {
    set -e
    set -x

    AKV_VAULT_NAME=${AKV_VAULT_NAME:-$1}
    if [ -z "$AKV_VAULT_NAME" ]; then
        read -p "Enter AKV name: " AKV_VAULT_NAME
    fi
    export AKV_VAULT_NAME

    AKV_KEY_NAME=${AKV_KEY_NAME:-$1}
    if [ -z "$AKV_KEY_NAME" ]; then
        read -p "Enter AKV Key name: " AKV_KEY_NAME
    fi
    export AKV_KEY_NAME

    # Convert the private key to PKCS8 format
    openssl pkcs8 -topk8 -nocrypt \
        -in $WORKSPACE/${AKV_KEY_NAME}_privk.pem \
        -out $WORKSPACE/${AKV_KEY_NAME}_privk-pkcs8.pem

    # Combine the public key with the private key
    cat $WORKSPACE/${AKV_KEY_NAME}_privk-pkcs8.pem \
        $WORKSPACE/${AKV_KEY_NAME}_cert.pem \
        > $WORKSPACE/${AKV_KEY_NAME}_combined_cert.pem

    az keyvault certificate import \
        --vault-name $AKV_VAULT_NAME \
        --name ${AKV_KEY_NAME}-${DEPLOYMENT_NAME} \
        --file $WORKSPACE/${AKV_KEY_NAME}_combined_cert.pem

    set +e
}

akv-key-import "$@"

jq -n '{
    AKV_KEY_NAME: env.AKV_KEY_NAME,
}'
