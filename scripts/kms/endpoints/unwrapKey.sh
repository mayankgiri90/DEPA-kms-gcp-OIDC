#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Callers should pass the wrapping key via --wrapping-key-file (path to PEM file)
# so the script can read it with jq --rawfile and send correct newlines to the server.
# Use --wrapping-key "string" only for literal values (e.g. invalid key tests).

unwrap_key() {
    auth="jwt"
    attestation=""
    wrappedKid=""
    wrappingKey=""
    wrappingKeyFile=""

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --attestation)
                attestation="$2"
                shift 2
                ;;
            --wrappedKid)
                wrappedKid="$2"
                shift 2
                ;;
            --wrapping-key)
                wrappingKey="$2"
                shift 2
                ;;
            --wrapping-key-file)
                wrappingKeyFile="$2"
                shift 2
                ;;
            --auth)
                auth="$2"
                shift 2
                ;;
            *)
                echo "Unknown parameter: $1"
                exit 1
                ;;
        esac
    done

    auth_arg=()
    if [[ "$auth" == "member_cert" ]]; then
        auth_arg=(--cert $KMS_MEMBER_CERT_PATH --key $KMS_MEMBER_PRIVK_PATH)
    elif [[ "$auth" == "user_cert" ]]; then
        auth_arg=(--cert $KMS_USER_CERT_PATH --key $KMS_USER_PRIVK_PATH)
    elif [[ "$auth" == "jwt" ]]; then
        auth_arg=(-H "Authorization: Bearer $(. $JWT_ISSUER_WORKSPACE/fetch.sh && jwt_issuer_fetch)")
    fi

    # Build JSON with jq. Use --rawfile when caller passes a file path (correct PEM newlines).
    if [[ -n "$wrappingKeyFile" && -f "$wrappingKeyFile" ]]; then
        payload=$(jq -n \
            --arg attestation_str "$attestation" \
            --arg wrappedKid "$wrappedKid" \
            --rawfile wrappingKey "$wrappingKeyFile" \
            '{attestation: ($attestation_str | fromjson),
              wrappedKid: $wrappedKid,
              wrapped: "",
              wrappingKey: $wrappingKey}')
    else
        payload=$(jq -n \
            --arg attestation_str "$attestation" \
            --arg wrappedKid "$wrappedKid" \
            --arg wrappingKey "$wrappingKey" \
            '{attestation: ($attestation_str | fromjson),
              wrappedKid: $wrappedKid,
              wrapped: "",
              wrappingKey: $wrappingKey}')
    fi

    curl $KMS_URL/app/unwrapKey \
        -X POST \
        --cacert $KMS_SERVICE_CERT_PATH \
        "${auth_arg[@]}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        -w '\n%{http_code}\n'
}

unwrap_key "$@"
