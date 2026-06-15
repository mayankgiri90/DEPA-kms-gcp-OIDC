// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { snp_attestation } from "@microsoft/ccf-app/global";
import { ServiceResult } from "../utils/ServiceResult";
import { IAttestationReport } from "./ISnpAttestationReport";
import { ISnpAttestation } from "./ISnpAttestation";
import { Base64 } from "js-base64";
import { SnpAttestationClaims } from "./SnpAttestationClaims";
import { Logger, LogContext } from "../utils/Logger";

/**
 * Validates a GCP Confidential VM SNP attestation.
 *
 * GCP Confidential VMs use AMD SEV-SNP hardware. This function verifies the attestation
 * signature using evidence, endorsements, uvm_endorsements, and endorsed_tcb.
 * 
 * Note: For GCP, we only verify attestation integrity and skip key release policy checks
 * (image hash validation). JWT validation at the endpoint level handles minimal claims
 * checks (issuer, etc.).
 */
export const validateGcpAttestation = (
  attestation: ISnpAttestation,
): ServiceResult<string | IAttestationReport> => {
  const logContext = new LogContext().appendScope("validateGcpAttestation");
  Logger.debug(`Start GCP attestation validation`, logContext);

  if (!attestation) {
    return ServiceResult.Failed<string>(
      { errorMessage: "missing attestation" },
      400,
      logContext,
    );
  }
  if (!attestation.evidence && typeof attestation.evidence !== "string") {
    return ServiceResult.Failed<string>(
      { errorMessage: "missing or bad attestation.evidence" },
      400,
      logContext,
    );
  }
  if (!attestation.endorsements && typeof attestation.endorsements !== "string") {
    return ServiceResult.Failed<string>(
      { errorMessage: "missing or bad attestation.endorsements" },
      400,
      logContext,
    );
  }
  if (!attestation.uvm_endorsements && typeof attestation.uvm_endorsements !== "string") {
    return ServiceResult.Failed<string>(
      { errorMessage: "missing or bad attestation.uvm_endorsements" },
      400,
      logContext,
    );
  }
  if (!attestation.endorsed_tcb && typeof attestation.endorsed_tcb !== "string") {
    return ServiceResult.Failed<string>(
      { errorMessage: "missing or bad attestation.endorsed_tcb" },
      400,
      logContext,
    );
  }

  let evidence: ArrayBuffer;
  let endorsements: ArrayBuffer;
  let uvm_endorsements: ArrayBuffer;

  try {
    evidence = ccfapp
      .typedArray(Uint8Array)
      .encode(Base64.toUint8Array(attestation.evidence) as Uint8Array<ArrayBuffer>);
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Malformed attestation.evidence" },
      400,
      logContext,
    );
  }
  try {
    endorsements = ccfapp
      .typedArray(Uint8Array)
      .encode(Base64.toUint8Array(attestation.endorsements) as Uint8Array<ArrayBuffer>);
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Malformed attestation.endorsements" },
      400,
      logContext,
    );
  }
  try {
    uvm_endorsements = ccfapp
      .typedArray(Uint8Array)
      .encode(Base64.toUint8Array(attestation.uvm_endorsements) as Uint8Array<ArrayBuffer>);
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Malformed attestation.uvm_endorsements" },
      400,
      logContext,
    );
  }

  try {
    const endorsed_tcb = attestation.endorsed_tcb;

    const attestationReport = snp_attestation.verifySnpAttestation(
      evidence,
      endorsements,
      uvm_endorsements,
      endorsed_tcb,
    );
    Logger.debug(
      `GCP attestation report: ${JSON.stringify(attestationReport)}`,
      logContext,
    );

    // For GCP, we skip key release policy validation (which would check image hash).
    // JWT validation at the endpoint level handles the minimal claims checks (issuer, etc.).
    // The attestation verification above ensures signature integrity.
    
    const claimsProvider = new SnpAttestationClaims(attestationReport);
    const attestationClaims = claimsProvider.getClaims();
    Logger.debug(`GCP attestation claims (for logging only): `, logContext, attestationClaims);

    // Return success after attestation signature verification
    return ServiceResult.Succeeded<IAttestationReport>(attestationClaims, logContext);
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: `GCP attestation error: ${exception.message}` },
      500,
      logContext,
    );
  }
};
