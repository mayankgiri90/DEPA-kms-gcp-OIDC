// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
import * as ccfapp from "@microsoft/ccf-app";
import { unwrapKeyGcp } from "./endpoints/keyEndpoint";

export * from "./endpoints/kms";
export * from "./endpoints/keyEndpoint";
export * from "./endpoints/publickeyEndpoint";
export * from "./endpoints/refreshEndpoint";
export * from "./endpoints/keyReleasePolicyEndpoint";
export * from "./endpoints/settingsPolicyEndpoint";
export * from "./endpoints/jwtValidationPolicyEndpoint";
export * from "./endpoints/IKeyItem";
export * from "./endpoints/KeyGeneration";
export * from "./endpoints/TinkKey";
export * from "./endpoints/proposals";
export * from "./policies/IKeyReleasePolicySnpProps";
export * from "./utils/Tooling";
export * from "./utils/ServiceResult";

// Register GCP unwrap endpoint
ccfapp.endpoints.register(
	"POST",
	"/app/unwrapKeyGcp",
	unwrapKeyGcp,
	["jwt"]
);
