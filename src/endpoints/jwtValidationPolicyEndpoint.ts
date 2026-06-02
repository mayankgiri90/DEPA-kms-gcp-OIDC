// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceRequest } from "../utils/ServiceRequest";
import { LogContext, Logger } from "../utils/Logger";
import { validationPolicyMapName } from "../authorization/jwt/JwtValidationPolicyMap";
import { ccf } from "@microsoft/ccf-app/global";

// Enable the endpoint
enableEndpoint();

/**
 * Retrieves the JWT validation policy for all issuers.
 * @returns A ServiceResult containing all JWT validation policies as an object with issuer as keys.
 */
export const jwtValidationPolicy = (
  request: ccfapp.Request<void>,
): ServiceResult<string | { [issuer: string]: { [key: string]: string } }> => {
  const logContext = new LogContext().appendScope("jwtValidationPolicyEndpoint");
  const serviceRequest = new ServiceRequest<void>(logContext, request);

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  try {
    // Return all policies
    const allPolicies: { [issuer: string]: { [key: string]: string } } = {};
    const validationPolicyMap = ccf.kv[validationPolicyMapName];
    
    validationPolicyMap.forEach((value, key) => {
      const issuerKey = ccf.bufToStr(key);
      const policyBuf = value;
      if (policyBuf !== undefined) {
        try {
          const policyStr = ccf.bufToStr(policyBuf);
          const policy = JSON.parse(policyStr);
          allPolicies[issuerKey] = policy;
          Logger.debug(`JWT validation policy for issuer ${issuerKey}: ${policyStr}`, logContext);
        } catch (error: any) {
          Logger.error(`Failed to parse policy for issuer ${issuerKey}: ${error.message}`, logContext);
        }
      }
    });

    return ServiceResult.Succeeded<{ [issuer: string]: { [key: string]: string } }>(allPolicies, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};

