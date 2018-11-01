#!/usr/bin/env bash

function helper::print_digest_example() {
    digest=$(echo -n 'grant_type=client_credentials&scope=create_order+granting+payment-requests+payment-requests%3Aview+payment-requests%3Acreate+payment-requests%3Aclose+virtual-ledger-accounts%3Afund-reservation%3Acreate+virtual-ledger-accounts%3Afund-reservation%3Adelete+virtual-ledger-accounts%3Abalance%3Aview'  | openssl dgst -sha256 -binary | openssl base64)
    echo "Actual digest:   ${digest}"
    echo "Expected digest: dCup+ZCaQczuxE5H2yw+rC+T1OepyGSd0IfIqRM2hHU="
}

function signed_request() {
    local METHOD=$1
    local PATHWITHOUTQUERY=$2
    local QUERY=$3
    local BODY=$4
    local ACCESS_TOKEN=$5

    local host="api.sandbox.ing.com"
    local clientId="example_client_id"
    local client_signing_key="./example_client_signing.key"
    local client_tls_key="./example_client_tls.key"
    local client_tls_cer="./example_client_tls.cer"

#    local host="api.ing.com"
#    local clientId="4caac2af-173e-481c-b02f-964f98607a8b"
#    local client_signing_key="./../server.key"
#    local client_tls_key="./../server.key"
#    local client_tls_cer="./../mutual_tls_1.crt"

    ### CONFIRMED WORKING DIGEST OF GRANT_TYPE
    # echo -n 'grant_type=client_credentials&scope=create_order+granting+payment-requests+payment-requests%3Aview+payment-requests%3Acreate+payment-requests%3Aclose+virtual-ledger-accounts%3Afund-reservation%3Acreate+virtual-ledger-accounts%3Afund-reservation%3Adelete+virtual-ledger-accounts%3Abalance%3Aview'  | openssl dgst -sha256 -binary | openssl base64
    # ABOVE COMMAND CORRECTLY OUTPUTS --> dCup+ZCaQczuxE5H2yw+rC+T1OepyGSd0IfIqRM2hHU=

    ## Change things below with care
    reqIdRandom=$(uuidgen)

    methodUpperCase=$(echo ${METHOD} | awk '{print toupper($0)}')
    methodLowerCase=$(echo ${METHOD} | awk '{print tolower($0)}')

    pathWithQuery="$PATHWITHOUTQUERY?$QUERY"
    base64Command="openssl base64 -A"

    httpDate=$(LANG=en_US date -u +%a,\ %d\ %b\ %Y\ %H:%M:%S\ GMT)
    reqId="$reqIdRandom"

    digest="SHA-256=$(echo -n "${BODY}" | openssl dgst -sha256 -binary | openssl base64)" # <---- CONFIRMED WORKING DIGEST!
    signingString="(request-target): $methodLowerCase $PATHWITHOUTQUERY\ndate: $httpDate\ndigest: $digest\nx-ing-reqid: $reqId"
    signature=$(printf "$signingString" | openssl dgst -sha256 -sign ${client_signing_key} -passin "pass:changeit" | ${base64Command})

    # Debugging: Consider using flags: -k -i. However, using these flags breaks jq
    if [[ -z "${ACCESS_TOKEN}" ]]; then
        curl -s -X "$methodUpperCase" --cert ${client_tls_cer} --key ${client_tls_key} \
            -H "Date: ${httpDate}" \
            -H "Digest: ${digest}" \
            -H "X-ING-ReqID: ${reqId}" \
            -H "Authorization: Signature keyId=\"${clientId}\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=${signature}" \
            -H 'Accept: application/json, application/json, application/*+json, application/*+json' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            -d "${BODY}" \
            'https://'"${host}$pathWithQuery"
    else
        curl -s -X "$methodUpperCase" --cert ${client_tls_cer} --key ${client_tls_key} \
            -H 'Accept: application/json, application/json, application/*+json, application/*+json' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Digest: ${digest}" \
            -H "Date: ${httpDate}" \
            -H "X-ING-ReqID: ${reqId}" \
            -H 'Signature: keyId="example_client_id",algorithm="rsa-sha256",headers="(request-target) date digest x-ing-reqid",signature="'${signature}'"' \
            --data "${BODY}" \
            'https://'"${host}$pathWithQuery"
    fi
}


# IMPORTANT - THE GRANT_TYPE ENCODING IS REALLY IFFY!
oauth2_token_response=$(signed_request "POST" "/oauth2/token" "" "grant_type=client_credentials&scope=create_order+granting+payment-requests+payment-requests%3Aview+payment-requests%3Acreate+payment-requests%3Aclose+virtual-ledger-accounts%3Afund-reservation%3Acreate+virtual-ledger-accounts%3Afund-reservation%3Adelete+virtual-ledger-accounts%3Abalance%3Aview")
oauth2_access_token=$(echo ${oauth2_token_response} | jq -r '.access_token')

if [[ -z ${oauth2_access_token} ]]; then
    echo "No application access code"
    exit 1
fi

echo "Step 1. Application access token: ${oauth2_access_token}"
scope="view_balance"
oauth2_auth_server_response=$(signed_request "GET" "/oauth2/authorization-server-url" "scope=${scope}&country_code=nl" "" "${oauth2_access_token}")
oauth2_auth_server_url=$(echo ${oauth2_auth_server_response} | jq -r '.location')
echo "Step 2. Ask client permission for [${scope}] using: ${oauth2_auth_server_url}"

oauth2_authorization_code="694d6ca9-1310-4d83-8dbb-e819c1ee6b80"
echo "Step 3. Simulator doesn't support authentication flow, using hardcoded authorization_code ${oauth2_authorization_code}"


oauth2_redirect_uri="xxx" # TODO: Production could be http://bla.io/oauth2/callback
oauth2_client_token_response=$(signed_request "POST" "/oauth2/token" "" "grant_type=authorization_code&code=694d6ca9-1310-4d83-8dbb-e819c1ee6b80&redirect_uri=xxx" "${oauth2_access_token}")
oauth2_client_access_token=$(echo ${oauth2_client_token_response} | jq -r '.access_token')
echo "Step 4. Client access token: ${oauth2_client_access_token}"

echo "Step 5. Request client's account information"
oauth2_auth_server_response=$(signed_request "GET" "/v1/accounts" "" "" "${oauth2_client_access_token}")
echo ${oauth2_auth_server_response} | jq
