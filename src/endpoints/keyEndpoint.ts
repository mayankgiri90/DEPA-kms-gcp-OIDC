// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ccf } from "@microsoft/ccf-app/global";
import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../utils/ServiceResult";
import { IWrapped, KeyWrapper } from "./KeyWrapper";
import { ISnpAttestation, AttestationProvider } from "../attestation/ISnpAttestation";
import { enableEndpoint, isPemPublicKey } from "../utils/Tooling";
import { IAttestationReport } from "../attestation/ISnpAttestationReport";
import { IKeyItem } from "./IKeyItem";
import { KeyGeneration } from "./KeyGeneration";
import { validateAttestation } from "../attestation/AttestationValidation";
import { hpkeKeyIdMap, hpkeKeysMap, keyRotationPolicyMap } from "../repositories/Maps";
import { ServiceRequest } from "../utils/ServiceRequest";
import { LogContext, Logger } from "../utils/Logger";
import { KeyRotationPolicy } from "../policies/KeyRotationPolicy";

// Enable the endpoint
enableEndpoint();

//#region Key endpoints interface
export interface IKeyRequest {
  attestation: ISnpAttestation;
  wrappingKey?: string;
  attestationType?: AttestationProvider;
}

export interface IKeyResponse {
  wrappedKid: string;
  receipt: string;
  wrapped: string;
}

interface IUnwrapRequest {
  wrapped: string;
  wrappedKid: string;
  attestation: ISnpAttestation;
  wrappingKey: string;
}
export interface IUnwrapResponse {
  wrapped: string;
  receipt: string;
}
//#endregion

/**
 * Checks if the request has a wrapping key and returns the wrapping key and its hash.
 * @param body - The request body containing the wrapping key.
 * @returns A ServiceResult object containing the wrapping key and its hash if it exists, or an error message if it is missing or invalid.
 */
const requestHasWrappingKey = (
  body: IUnwrapRequest,
  logContextIn?: LogContext,
): ServiceResult<{ wrappingKey: ArrayBuffer; wrappingKeyHash: string }> => {
  const logContext = (logContextIn?.clone() || new LogContext()).appendScope("requestHasWrappingKey");
  let wrappingKey = body.wrappingKey;
  let wrappingKeyBuf: ArrayBuffer;
  let wrappingKeyHash: string;
  if (wrappingKey) {
    Logger.debug(`requestHasWrappingKey=> wrappingKey: '${wrappingKey}'`);
    const keyStr = String(wrappingKey);
    const hasBegin = keyStr.includes("-----BEGIN PUBLIC KEY-----");
    const hasEnd = keyStr.includes("-----END PUBLIC KEY-----");
    const hasLiteralNewline = keyStr.includes("\\n");
    const hasActualNewline = keyStr.includes("\n");
    
    if (!isPemPublicKey(wrappingKey)) {
      Logger.error(`Key-> Not a pem key`);
      const diagnosticHeaders = {
        "x-ms-kms-error-code": "INVALID_PEM_FORMAT",
        "x-ms-kms-error-details": `has_begin:${hasBegin},has_end:${hasEnd},has_literal_nl:${hasLiteralNewline},has_actual_nl:${hasActualNewline}`
      };
      return ServiceResult.Failed<{
        wrappingKey: ArrayBuffer;
        wrappingKeyHash: string;
      }>(
        {
          errorMessage: `${wrappingKey} not a PEM public key`,
        },
        400,
        logContext,
        diagnosticHeaders
      );
    }
    wrappingKeyBuf = ccf.strToBuf(wrappingKey);
    wrappingKeyHash = KeyGeneration.calculateHexHash(wrappingKeyBuf);
    Logger.debug(`Key->wrapping key hash: ${wrappingKeyHash}`);
    return ServiceResult.Succeeded({
      wrappingKey: wrappingKeyBuf,
      wrappingKeyHash,
    }, logContext);
  }

  return ServiceResult.Failed<{
    wrappingKey: ArrayBuffer;
    wrappingKeyHash: string;
  }>(
    {
      errorMessage: `Missing wrappingKey`,
    },
    400,
    logContext
  );
};

//#region KMS Key endpoints
// Get latest private key
export const key = (
  request: ccfapp.Request<IKeyRequest>,
): ServiceResult<string | IKeyResponse> => {
  const name = "key";
  const logContext = new LogContext().appendScope(name);
  const serviceRequest = new ServiceRequest<IKeyRequest>(logContext, request);
  let attestation: ISnpAttestation | undefined = undefined;

  // Check if serviceRequest.body is defined before accessing "attestation"
  if (serviceRequest.body && serviceRequest.body["attestation"]) {
    attestation = serviceRequest.body["attestation"];
  }

  // Validate input
  if (!serviceRequest.body || !attestation) {
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: The body is not a ${name} request: ${JSON.stringify(serviceRequest.body)}`,
      },
      400,
      logContext
    );
  }

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  const attestationProvider: AttestationProvider = serviceRequest.body["attestationType"] || "azure";

  let kid = serviceRequest.query?.["kid"];
  let id: number | undefined;
  if (kid === undefined) {
    [id, kid] = hpkeKeyIdMap.latestItem();
    if (kid === undefined) {
      return ServiceResult.Failed<string>(
        { errorMessage: `${name}: No keys in store` },
        400,
        logContext
      );
    }
  }

  const fmt = serviceRequest.query?.["fmt"] || "jwk";
  if (!(fmt === "jwk" || fmt === "tink")) {
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: Wrong fmt query parameter '${fmt}'. Must be jwt or tink.`,
      },
      400,
      logContext
    );
  }

  let validateAttestationResult: ServiceResult<string | IAttestationReport>;
  try {
    validateAttestationResult = validateAttestation(attestation, attestationProvider);
    if (!validateAttestationResult.success) {
      return ServiceResult.Failed<string>(
        validateAttestationResult.error!,
        validateAttestationResult.statusCode,
        logContext
      );
    }
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: Error in validating attestation (${attestation}): ${exception.message}`,
      },
      500,
      logContext
    );
  }

  // Be sure to request item and the receipt
  Logger.debug(`Get key with kid ${kid}`);
  const keyItem = hpkeKeysMap.store.get(kid) as IKeyItem;
  if (keyItem === undefined) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: kid ${kid} not found in store` },
      404,
      logContext
    );
  }

  const receipt = hpkeKeysMap.receipt(kid) || "";

  if (validateAttestationResult.statusCode === 202) {
    return ServiceResult.Accepted(logContext);
  }

  // Get wrapped key
  try {
    let wrapped: string | IWrapped;
    if (fmt == "tink") {
      wrapped = KeyWrapper.wrapKeyTink(undefined, keyItem);
      wrapped = JSON.stringify(wrapped);
    } else {
      // Default is JWT.
      wrapped = KeyWrapper.wrapKeyJwt(undefined, keyItem);
    }

    const response: IKeyResponse = {
      wrappedKid: kid,
      wrapped,
      receipt,
    };
    return ServiceResult.Succeeded(response, logContext);
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: Error Key (${id}): ${exception.message}` },
      500,
      logContext
    );
  }
};

/**
 * Unwrap private key
 *
 * @param request - The request object containing the key unwrapping details.
 * @returns A `ServiceResult` containing either the unwrapped key or an error message.
 */
export const unwrapKey = (
  request: ccfapp.Request<IUnwrapRequest>,
): ServiceResult<string | IUnwrapResponse> => {
  const name = "unwrapKey";
  const logContext = new LogContext().appendScope(name);
  const serviceRequest = new ServiceRequest<IKeyRequest>(logContext, request);

  let attestation: ISnpAttestation | undefined = undefined;

  // Check if serviceRequest.body is defined before accessing "attestation"
  if (serviceRequest.body && serviceRequest.body["attestation"]) {
    attestation = serviceRequest.body["attestation"];
  }

  // Repeat the check wherever serviceRequest.body["attestation"] is accessed
  if (serviceRequest.body && serviceRequest.body["attestation"]) {
    attestation = serviceRequest.body["attestation"];
  }

  // Validate input
  if (!serviceRequest.body || !attestation) {
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: The body is not a ${name} request: ${JSON.stringify(serviceRequest.body)}`,
      },
      400,
      logContext
    );
  }

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  // check payload
  const wrappedKid: string = serviceRequest.body["wrappedKid"];
  if (wrappedKid === undefined) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "MISSING_WRAPPED_KID",
      "x-ms-kms-error-details": `body_keys:${Object.keys(serviceRequest.body).join(",")}`,
      "x-ms-kms-has-wrapping-key": String(!!serviceRequest.body["wrappingKey"]),
      "x-ms-kms-has-attestation": String(!!serviceRequest.body["attestation"])
    };
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: Missing  ${name} wrappedKid in request: ${JSON.stringify(serviceRequest.body)}`,
      },
      400,
      logContext,
      diagnosticHeaders
    );
  }

  const wrappingKeyFromRequest = requestHasWrappingKey(
    serviceRequest.body as IUnwrapRequest,
  );
  if (wrappingKeyFromRequest.success === false) {
    // WrappingKey has errors - preserve headers from requestHasWrappingKey and merge with additional context
    const wrappingKey = serviceRequest.body["wrappingKey"];
    const existingHeaders = wrappingKeyFromRequest.headers || {};
    const diagnosticHeaders = {
      ...existingHeaders,
      // Only add these if they don't already exist from requestHasWrappingKey
      "x-ms-kms-error-code": existingHeaders["x-ms-kms-error-code"] || "WRAPPING_KEY_ERROR",
      "x-ms-kms-error-details": existingHeaders["x-ms-kms-error-details"] || `status_code:${wrappingKeyFromRequest.statusCode}`,
      "x-ms-kms-wrapping-key-exists": String(!!wrappingKey),
      "x-ms-kms-wrapping-key-length": wrappingKey ? String(wrappingKey).length : "0"
    };
    return ServiceResult.Failed<string>(
      wrappingKeyFromRequest.error!,
      wrappingKeyFromRequest.statusCode,
      logContext,
      diagnosticHeaders
    );
  }

  const wrappingKeyBuf = wrappingKeyFromRequest.body!.wrappingKey;
  const wrappingKeyHash = KeyGeneration.calculateHexHash(wrappingKeyBuf);
  Logger.debug(`unwrapKey->wrapping key hash: ${wrappingKeyHash}`);

  const attestationProvider: AttestationProvider = serviceRequest.body["attestationType"] || "azure";

  const fmt = serviceRequest.query?.["fmt"] || "jwk";
  if (!(fmt === "jwk" || fmt === "tink")) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "INVALID_FMT_PARAMETER",
      "x-ms-kms-error-details": `fmt_received:${fmt},fmt_valid:jwk,tink`
    };
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: Wrong fmt query parameter '${fmt}'. Must be jwt or tink.`,
      },
      400,
      logContext,
      diagnosticHeaders
    );
  }

  // Validate attestation
  let validateAttestationResult: ServiceResult<string | IAttestationReport>;
  try {
    validateAttestationResult = validateAttestation(attestation, attestationProvider);
    if (!validateAttestationResult.success) {
      const diagnosticHeaders = {
        "x-ms-kms-error-code": "ATTESTATION_VALIDATION_FAILED",
        "x-ms-kms-error-details": `status_code:${validateAttestationResult.statusCode}`,
        "x-ms-kms-attestation-has-evidence": String(!!attestation.evidence),
        "x-ms-kms-attestation-has-endorsements": String(!!attestation.endorsements)
      };
      return ServiceResult.Failed<string>(
        validateAttestationResult.error!,
        validateAttestationResult.statusCode,
        logContext,
        diagnosticHeaders
      );
    }
  } catch (exception: any) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "ATTESTATION_VALIDATION_EXCEPTION",
      "x-ms-kms-error-details": `exception:${exception.message}`
    };
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}: Error in validating attestation (${attestation}): ${exception.message}`,
      },
      500,
      logContext,
      diagnosticHeaders
    );
  }

  // Check if wrapping key match attestation
  const reportData = validateAttestationResult.body!["x-ms-sevsnpvm-reportdata"];
  if (!reportData.startsWith(wrappingKeyHash)) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "WRAPPING_KEY_HASH_MISMATCH",
      "x-ms-kms-error-details": `expected_prefix:${wrappingKeyHash.substring(0, 16)}...,actual_prefix:${reportData.substring(0, 16)}...`
    };
    return ServiceResult.Failed<string>(
      {
        errorMessage: `${name}:wrapping key hash ${reportData} does not match wrappingKey`,
      },
      400,
      logContext,
      diagnosticHeaders
    );
  }

  // Be sure to request item and the receipt
  Logger.debug(`Get key with kid ${wrappedKid}`);
  const keyItem = hpkeKeysMap.store.get(wrappedKid) as IKeyItem;
  if (keyItem === undefined) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "KEY_NOT_FOUND",
      "x-ms-kms-error-details": `wrapped_kid:${wrappedKid}`
    };
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}:kid ${wrappedKid} not found in store` },
      404,
      logContext,
      diagnosticHeaders
    );
  }

  const [expired, _depricated] = KeyRotationPolicy.isExpired(keyRotationPolicyMap, keyItem, logContext);
  if (expired) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "KEY_EXPIRED",
      "x-ms-kms-error-details": `wrapped_kid:${wrappedKid}`
    };
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}:kid ${wrappedKid} has expired` },
      410,  // 410 Gone, key no longer available
      logContext,
      diagnosticHeaders
    );
  }

  const receipt = hpkeKeysMap.receipt(wrappedKid) || "";

  // Get receipt if available, otherwise return accepted
  if (receipt !== undefined) {
    keyItem.receipt = receipt;
    Logger.debug(`Key->Receipt: ${receipt}`);
  } else {
    return ServiceResult.Accepted(logContext);
  }

  // Get wrapped key
  try {
    if (fmt == "tink") {
      Logger.debug(`Retrieve key in tink format`);
      const wrapped = KeyWrapper.createWrappedPrivateTinkKey(
        wrappingKeyBuf,
        keyItem,
      );
      const ret: IUnwrapResponse = { wrapped, receipt };
      return ServiceResult.Succeeded<IUnwrapResponse>(ret, logContext);
    } else {
      // Default is JWT.
      const wrapped = KeyWrapper.wrapKeyJwt(wrappingKeyBuf, keyItem);
      const ret = { wrapped, receipt };
      return ServiceResult.Succeeded<IUnwrapResponse>(ret, logContext);
    }
  } catch (exception: any) {
    const diagnosticHeaders = {
      "x-ms-kms-error-code": "WRAP_KEY_EXCEPTION",
      "x-ms-kms-error-details": `wrapped_kid:${wrappedKid},fmt:${fmt},exception:${exception.message}`
    };
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: Error (${wrappedKid}): ${exception.message}` },
      500,
      logContext,
      diagnosticHeaders
    );
  }
};

/**
 * Unwrap private key using GCP OIDC JWT attestation
 * 
 * Accepts:
 *   Authorization: Bearer <GCP Confidential Space OIDC JWT>
 *   Body: { wrappingKey: "<RSA-4096 public key PEM>" }
 * 
 * Returns: { wrappedKid, wrapped, receipt }
 */
export const unwrapKeyGcp = (
  request: ccfapp.Request<{ wrappingKey: string }>,
): ServiceResult<string | IKeyResponse> => {
  const name = "unwrapKeyGcp";
  const logContext = new LogContext().appendScope(name);
  const serviceRequest = new ServiceRequest<{ wrappingKey: string }>(logContext, request);

  // check if caller has a valid JWT identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  // Validate wrapping key exists in body
  if (!serviceRequest.body || !serviceRequest.body["wrappingKey"]) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: Missing wrappingKey in request body` },
      400,
      logContext
    );
  }

  const wrappingKey = serviceRequest.body["wrappingKey"];

  // Validate it is a valid PEM public key
  if (!isPemPublicKey(wrappingKey)) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: wrappingKey is not a valid PEM public key` },
      400,
      logContext
    );
  }

  const wrappingKeyFromRequest = requestHasWrappingKey(
    serviceRequest.body as IUnwrapRequest,
  );
  if (wrappingKeyFromRequest.success === false) {
    return wrappingKeyFromRequest;
  }
  const { wrappingKey: wrappingKeyBuf, wrappingKeyHash } = wrappingKeyFromRequest.body!;
  Logger.debug(`${name}->wrapping key hash: ${wrappingKeyHash}`);

  // Get latest key
  const [id, kid] = hpkeKeyIdMap.latestItem();
  if (kid === undefined) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: No keys in store` },
      400,
      logContext
    );
  }

  const keyItem = hpkeKeysMap.store.get(kid) as IKeyItem;
  if (keyItem === undefined) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: kid ${kid} not found in store` },
      404,
      logContext
    );
  }

  const receipt = hpkeKeysMap.receipt(kid) || "";

  // Wrap the key with the RSA public key
  try {
    const wrapped = KeyWrapper.wrapKeyJwt(wrappingKeyBuf, keyItem);
    const response: IKeyResponse = {
      wrappedKid: kid,
      wrapped,
      receipt,
    };
    return ServiceResult.Succeeded(response, logContext);
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: `${name}: Error wrapping key: ${exception.message}` },
      500,
      logContext
    );
  }
};

//#endregion
