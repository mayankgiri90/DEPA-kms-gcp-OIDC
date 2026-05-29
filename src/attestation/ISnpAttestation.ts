// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

export type AttestationProvider = "azure" | "gcp";

export interface ISnpAttestation {
  evidence: string;
  endorsements: string;
  uvm_endorsements: string;
  endorsed_tcb: string;
  attestationType?: AttestationProvider;
}
