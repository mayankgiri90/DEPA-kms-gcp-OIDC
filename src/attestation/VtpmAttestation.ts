// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { SnpAttestationResult } from "@microsoft/ccf-app/global";

/**
 * AMD SEV-SNP launch measurements for GCP Confidential VMs, keyed by vCPU count.
 * These are the x-ms-sevsnpvm-launchmeasurement values to include in the GCP key
 * release policy (set_gcp_key_release_policy action, "x-ms-sevsnpvm-launchmeasurement" claim).
 */
export const GCP_VCPU_MEASUREMENTS: Record<number, string> = {
  1:   "9fee1c2d9279a6f330c728e17e5427685558604a141486dcb549da5b81c7492cdfd3fc4c1a3552bd9b6af65930b20641",
  2:   "7a5ed176bad8a9ff02cebb94b24b076a0b1905042a85d9fca7670d3a3ff466db3b1c2b76f8eca888f8d806d2ec92434e",
  4:   "ad532545a87f7ebba7ded856946f9f638d4395fe8ae6b82b694668774546fc4a5f3f7bf6eb389380743f39dffdf1bccc",
  8:   "0395ba843be8a2d2119eef812e562b9c26bcb1015fb465d448addd200dc90bb880f287ee367fddecedd89ce73162a62c",
  16:  "10f343779aa9a95ba781c9a39db9fde3ef611aeac8d2f516cc750f48a363a1bb67440dc8595e8dafa855326aa4356e4c",
  24:  "539a2d13373db75fd758219ec7c341ce9921b063d33efb88055f38bb4e4b7c3bf140d0a2589afa9292bfb6c7a787bafb",
  32:  "591b1103647089d793ffeaad653eaa2394972c09a4bc0178bf76b77860151b7b9c70856b0a36c4d421a74cf84a19944a",
  48:  "56df6081776e76d374152d5343060771f24acfdd75c3af4b360c91b9b26e43c2fab0a2157a5a746c929b2a342dbda54b",
  64:  "94cd8c643cf5ec38966b8243a908ddc2abea1b4922bd04d57ba0bb38df8f8f4ac7e6c70bad6d1672df81ccd2ee26605b",
  80:  "60ce03d7ee1a0fffcf3c865202371ba38856b6c1f2edcfb42ba0cc2e980d0eb15f18abd0450c34519ac73ca7c838855b",
  96:  "d4e07619f794b16a0e73ec742f947fdb773947082a5c506cf0fb1bfc63cb0aaa571eb792ad04e90d7601bc500373386e",
  112: "182fe328f4abaccfde4b4041856a745577c22457018646eff585e1ba4c7179fa7b86abdb3d9f27d52b168ac924199bc3",
  128: "ce64dfb5dcd3ad66bc488f5badb7b45b2374beb1f3926ea96fd59b62ac77ee9a802f7432ea6607d5772e166812d6a638",
};

/** All valid GCP launch measurements (union across all vCPU counts). */
export const GCP_VALID_MEASUREMENTS: string[] = Object.values(GCP_VCPU_MEASUREMENTS);

export interface PcrSelectionEntry {
  hash_algorithm: number;
  pcr_indices: number[];
}

export interface VtpmAttestationResult {
  snp_attestation: SnpAttestationResult["attestation"];
  ek_pub_hash_verified: boolean;
  ek_pub_hash_field: string;
  pcr_digest: ArrayBuffer;
  pcr_selection: PcrSelectionEntry[];
  /** Hex-encoded uint64 (e.g. "0x0000000600000004") to avoid JS precision loss */
  firmware_version: string;
  nonce: ArrayBuffer;
  uvm_endorsements?: {
    did: string;
    feed: string;
    svn: string;
  };
}

// Hardcoded test result for GCP vTPM attestation.
// TODO: Replace with actual vTPM attestation verification when GCP integration is ready.
export const HARDCODED_GCP_VTPM_RESULT: VtpmAttestationResult = {
  snp_attestation: {
    version: 2,
    guest_svn: 0,
    policy: {
      abi_minor: 0,
      abi_major: 0,
      smt: 1,
      migrate_ma: 0,
      debug: 0,
      single_socket: 0,
    },
    family_id: new Uint8Array(16).buffer,
    image_id: new Uint8Array(16).buffer,
    vmpl: 0,
    signature_algo: 1,
    platform_version: {
      boot_loader: 3,
      tee: 0,
      snp: 8,
      microcode: 115,
    },
    platform_info: {
      smt_en: 1,
      tsme_en: 0,
    },
    flags: {
      author_key_en: 0,
      mask_chip_key: 0,
      signing_key: 0,
    },
    report_data: new Uint8Array(64).buffer,
    measurement: new Uint8Array(48).buffer,
    host_data: new Uint8Array(32).buffer,
    id_key_digest: new Uint8Array(48).buffer,
    author_key_digest: new Uint8Array(48).buffer,
    report_id: new Uint8Array(32).buffer,
    report_id_ma: new Uint8Array(32).buffer,
    reported_tcb: {
      boot_loader: 3,
      tee: 0,
      snp: 8,
      microcode: 115,
    },
    cpuid_fam_id: 0,
    cpuid_mod_id: 0,
    cpuid_step: 0,
    chip_id: new Uint8Array(64).buffer,
    committed_tcb: {
      boot_loader: 3,
      tee: 0,
      snp: 8,
      microcode: 115,
    },
    current_minor: 0,
    current_build: 0,
    current_major: 0,
    committed_minor: 0,
    committed_build: 0,
    committed_major: 0,
    launch_tcb: {
      boot_loader: 3,
      tee: 0,
      snp: 8,
      microcode: 115,
    },
    signature: {
      r: new Uint8Array(72).buffer,
      s: new Uint8Array(72).buffer,
    },
  },
  ek_pub_hash_verified: true,
  ek_pub_hash_field: "0000000000000000000000000000000000000000000000000000000000000000",
  pcr_digest: new Uint8Array(32).buffer,
  pcr_selection: [
    { hash_algorithm: 4, pcr_indices: [0, 1, 2, 3, 4, 5, 6, 7] },
  ],
  firmware_version: "0x0000000600000004",
  nonce: new Uint8Array(32).buffer,
  uvm_endorsements: {
    did: "did:x509:0:sha256:test_gcp_did",
    feed: "test-gcp-feed",
    svn: "1",
  },
};
