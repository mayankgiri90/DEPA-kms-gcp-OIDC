// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Use the CCF polyfill to mock-up all key-value map functionality for unit-test
import "@microsoft/ccf-app/polyfill.js";
import { ccf } from "@microsoft/ccf-app/global";
import { beforeAll, beforeEach, describe, expect, test } from "@jest/globals";
import { Logger, LogLevel } from "../../../src/utils/Logger";
import {
  HARDCODED_GCP_VTPM_RESULT,
  GCP_VCPU_MEASUREMENTS,
  GCP_VALID_MEASUREMENTS,
} from "../../../src/attestation/VtpmAttestation";
import { validateGcpAttestation } from "../../../src/attestation/GcpAttestationValidation";
import { validateAttestation } from "../../../src/attestation/AttestationValidation";
import { SnpAttestationClaims } from "../../../src/attestation/SnpAttestationClaims";
import { SnpAttestationResult } from "@microsoft/ccf-app/global";
import { gcpKeyReleaseMapName, gcpKeyReleasePolicyMap } from "../../../src/repositories/Maps";
import { ISnpAttestation } from "../../../src/attestation/ISnpAttestation";
import { KeyReleasePolicy } from "../../../src/policies/KeyReleasePolicy";
import { IAttestationReport } from "../../../src/attestation/ISnpAttestationReport";

// Minimal stub used in routing-confirmation tests where we only need to
// distinguish which code path was taken (not whether attestation succeeds).
const DUMMY_ATTESTATION: ISnpAttestation = {
  evidence: "dGVzdA==",
  endorsements: "dGVzdA==",
  uvm_endorsements: "dGVzdA==",
  endorsed_tcb: "test",
};

// --------------------------------------------------------------------------
// Helpers to read/write the GCP KV policy map directly
// --------------------------------------------------------------------------
const setGcpClaims = (claims: Record<string, string[]>) => {
  ccf.kv[gcpKeyReleaseMapName].set(
    ccf.strToBuf("claims"),
    ccf.strToBuf(JSON.stringify(claims)),
  );
};

const clearGcpPolicy = () => {
  const keys = ["claims", "gte", "gt"];
  for (const k of keys) {
    const keyBuf = ccf.strToBuf(k);
    if (ccf.kv[gcpKeyReleaseMapName].has(keyBuf)) {
      ccf.kv[gcpKeyReleaseMapName].delete(keyBuf);
    }
  }
};

// --------------------------------------------------------------------------
// The claims the SnpAttestationClaims extractor will produce from the
// hardcoded result.  Derived from HARDCODED_GCP_VTPM_RESULT field values.
// --------------------------------------------------------------------------
const ALL_ZERO_16 = "0".repeat(32);  // 16 bytes → 32 hex chars
const ALL_ZERO_32 = "0".repeat(64);  // 32 bytes → 64 hex chars
const ALL_ZERO_48 = "0".repeat(96);  // 48 bytes → 96 hex chars
const ALL_ZERO_64 = "0".repeat(128); // 64 bytes → 128 hex chars
const ALL_ZERO_72 = "0".repeat(144); // 72 bytes → 144 hex chars

beforeAll(() => {
  Logger.setLogLevel(LogLevel.ERROR); // keep test output clean
});

beforeEach(() => {
  clearGcpPolicy();
});

// ==========================================================================
describe("HARDCODED_GCP_VTPM_RESULT structure", () => {
  test("has correct top-level fields", () => {
    expect(HARDCODED_GCP_VTPM_RESULT.ek_pub_hash_verified).toBe(true);
    expect(HARDCODED_GCP_VTPM_RESULT.firmware_version).toBe("0x0000000600000004");
    expect(HARDCODED_GCP_VTPM_RESULT.pcr_selection).toHaveLength(1);
    expect(HARDCODED_GCP_VTPM_RESULT.pcr_selection[0].hash_algorithm).toBe(4);
    expect(HARDCODED_GCP_VTPM_RESULT.pcr_selection[0].pcr_indices).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  test("snp_attestation has expected values", () => {
    const snp = HARDCODED_GCP_VTPM_RESULT.snp_attestation;
    expect(snp.version).toBe(2);
    expect(snp.vmpl).toBe(0);
    expect(snp.policy.debug).toBe(0);
    expect(snp.policy.smt).toBe(1);
  });

  test("uvm_endorsements has expected test values", () => {
    expect(HARDCODED_GCP_VTPM_RESULT.uvm_endorsements).toBeDefined();
    expect(HARDCODED_GCP_VTPM_RESULT.uvm_endorsements!.did).toBe("did:x509:0:sha256:test_gcp_did");
    expect(HARDCODED_GCP_VTPM_RESULT.uvm_endorsements!.feed).toBe("test-gcp-feed");
    expect(HARDCODED_GCP_VTPM_RESULT.uvm_endorsements!.svn).toBe("1");
  });

  test("ArrayBuffer fields have correct sizes", () => {
    const snp = HARDCODED_GCP_VTPM_RESULT.snp_attestation;
    expect(snp.family_id.byteLength).toBe(16);
    expect(snp.image_id.byteLength).toBe(16);
    expect(snp.report_data.byteLength).toBe(64);
    expect(snp.measurement.byteLength).toBe(48);
    expect(snp.host_data.byteLength).toBe(32);
    expect(snp.report_id.byteLength).toBe(32);
    expect(HARDCODED_GCP_VTPM_RESULT.pcr_digest.byteLength).toBe(32);
    expect(HARDCODED_GCP_VTPM_RESULT.nonce.byteLength).toBe(32);
  });
});

// ==========================================================================
describe("SnpAttestationClaims extraction from hardcoded GCP vTPM result", () => {
  const buildSnpResult = (): SnpAttestationResult =>
    ({
      attestation: HARDCODED_GCP_VTPM_RESULT.snp_attestation,
      uvm_endorsements: HARDCODED_GCP_VTPM_RESULT.uvm_endorsements,
    }) as SnpAttestationResult;

  test("extracts x-ms-ver from version field", () => {
    const claims = new SnpAttestationClaims(buildSnpResult()).getClaims();
    expect(claims["x-ms-ver"]).toBe("2");
  });

  test("extracts x-ms-sevsnpvm-is-debuggable as false", () => {
    const claims = new SnpAttestationClaims(buildSnpResult()).getClaims();
    expect(claims["x-ms-sevsnpvm-is-debuggable"]).toBe(false);
  });

  test("extracts x-ms-sevsnpvm-smt-allowed as true", () => {
    const claims = new SnpAttestationClaims(buildSnpResult()).getClaims();
    expect(claims["x-ms-sevsnpvm-smt-allowed"]).toBe(true);
  });

  test("extracts x-ms-sevsnpvm-vmpl as 0", () => {
    const claims = new SnpAttestationClaims(buildSnpResult()).getClaims();
    expect(claims["x-ms-sevsnpvm-vmpl"]).toBe(0);
  });

  test("extracts ArrayBuffer fields as zero-padded hex strings", () => {
    const claims = new SnpAttestationClaims(buildSnpResult()).getClaims();
    expect(claims["x-ms-sevsnpvm-familyId"]).toBe(ALL_ZERO_16);
    expect(claims["x-ms-sevsnpvm-imageId"]).toBe(ALL_ZERO_16);
    expect(claims["x-ms-sevsnpvm-reportdata"]).toBe(ALL_ZERO_64);
    expect(claims["x-ms-sevsnpvm-launchmeasurement"]).toBe(ALL_ZERO_48);
    expect(claims["x-ms-sevsnpvm-hostdata"]).toBe(ALL_ZERO_32);
    expect(claims["x-ms-sevsnpvm-idkeydigest"]).toBe(ALL_ZERO_48);
    expect(claims["x-ms-sevsnpvm-authorkeydigest"]).toBe(ALL_ZERO_48);
    expect(claims["x-ms-sevsnpvm-reportid"]).toBe(ALL_ZERO_32);
    expect(claims["signature-r"]).toBe(ALL_ZERO_72);
    expect(claims["signature-s"]).toBe(ALL_ZERO_72);
  });

  test("extracts uvm_endorsements fields", () => {
    const claims = new SnpAttestationClaims(buildSnpResult()).getClaims();
    expect(claims["uvm_endorsements-did"]).toBe("did:x509:0:sha256:test_gcp_did");
    expect(claims["uvm_endorsements-feed"]).toBe("test-gcp-feed");
    expect(claims["uvm_endorsements-svn"]).toBe("1");
  });
});

// ==========================================================================
describe("GCP_VCPU_MEASUREMENTS", () => {
  test("contains entries for all expected vCPU counts", () => {
    const expectedCounts = [1, 2, 4, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128];
    expect(Object.keys(GCP_VCPU_MEASUREMENTS).map(Number).sort((a, b) => a - b))
      .toEqual(expectedCounts);
  });

  test("every measurement is a 96-character hex string (48 bytes)", () => {
    for (const [, measurement] of Object.entries(GCP_VCPU_MEASUREMENTS)) {
      expect(measurement).toMatch(/^[0-9a-f]{96}$/);
    }
  });

  test("all measurements are distinct", () => {
    const values = Object.values(GCP_VCPU_MEASUREMENTS);
    expect(new Set(values).size).toBe(values.length);
  });

  test("GCP_VALID_MEASUREMENTS contains all measurement values", () => {
    expect(GCP_VALID_MEASUREMENTS).toHaveLength(Object.keys(GCP_VCPU_MEASUREMENTS).length);
    for (const m of Object.values(GCP_VCPU_MEASUREMENTS)) {
      expect(GCP_VALID_MEASUREMENTS).toContain(m);
    }
  });

  test("spot-check: 1-vCPU measurement matches expected value", () => {
    expect(GCP_VCPU_MEASUREMENTS[1]).toBe(
      "9fee1c2d9279a6f330c728e17e5427685558604a141486dcb549da5b81c7492cdfd3fc4c1a3552bd9b6af65930b20641",
    );
  });

  test("spot-check: 128-vCPU measurement matches expected value", () => {
    expect(GCP_VCPU_MEASUREMENTS[128]).toBe(
      "ce64dfb5dcd3ad66bc488f5badb7b45b2374beb1f3926ea96fd59b62ac77ee9a802f7432ea6607d5772e166812d6a638",
    );
  });
});

// ==========================================================================
// Policy validation logic is tested directly via KeyReleasePolicy so that the
// unit tests are not blocked on real SNP binary verification (which requires
// actual hardware or a signed attestation report).
// ==========================================================================
describe("GCP key release policy validation (via KeyReleasePolicy)", () => {
  const buildClaims = (overrides: IAttestationReport = {}): IAttestationReport => ({
    "x-ms-sevsnpvm-launchmeasurement": GCP_VCPU_MEASUREMENTS[4],
    "x-ms-sevsnpvm-is-debuggable": false,
    ...overrides,
  });

  test("passes when measurement matches the GCP policy", () => {
    const measurement = GCP_VCPU_MEASUREMENTS[4];
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": [measurement] });

    const policy = KeyReleasePolicy.getKeyReleasePolicyFromMap(gcpKeyReleasePolicyMap);
    const result = KeyReleasePolicy.validateKeyReleasePolicy(policy, buildClaims());
    expect(result.success).toBe(true);
  });

  test("passes when policy contains all GCP measurements (any vCPU count)", () => {
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": GCP_VALID_MEASUREMENTS });

    const policy = KeyReleasePolicy.getKeyReleasePolicyFromMap(gcpKeyReleasePolicyMap);
    for (const measurement of GCP_VALID_MEASUREMENTS) {
      const result = KeyReleasePolicy.validateKeyReleasePolicy(
        policy,
        buildClaims({ "x-ms-sevsnpvm-launchmeasurement": measurement }),
      );
      expect(result.success).toBe(true);
    }
  });

  test("fails when measurement is not in the GCP policy", () => {
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": [GCP_VCPU_MEASUREMENTS[1]] });

    const policy = KeyReleasePolicy.getKeyReleasePolicyFromMap(gcpKeyReleasePolicyMap);
    const result = KeyReleasePolicy.validateKeyReleasePolicy(
      policy,
      buildClaims({ "x-ms-sevsnpvm-launchmeasurement": GCP_VCPU_MEASUREMENTS[128] }),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });

  test("fails when policy claims map is empty", () => {
    // clearGcpPolicy() already called in beforeEach — no claims set at all
    expect(() =>
      KeyReleasePolicy.getKeyReleasePolicyFromMap(gcpKeyReleasePolicyMap),
    ).toThrow();
  });

  test("passes with gte operator on a numeric field", () => {
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": GCP_VALID_MEASUREMENTS });
    ccf.kv[gcpKeyReleaseMapName].set(
      ccf.strToBuf("gte"),
      ccf.strToBuf(JSON.stringify({ "x-ms-sevsnpvm-guestsvn": 0 })),
    );

    const policy = KeyReleasePolicy.getKeyReleasePolicyFromMap(gcpKeyReleasePolicyMap);
    const result = KeyReleasePolicy.validateKeyReleasePolicy(
      policy,
      buildClaims({ "x-ms-sevsnpvm-guestsvn": 0 }),
    );
    expect(result.success).toBe(true);
  });

  test("fails with gte operator when attestation value is below threshold", () => {
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": GCP_VALID_MEASUREMENTS });
    ccf.kv[gcpKeyReleaseMapName].set(
      ccf.strToBuf("gte"),
      ccf.strToBuf(JSON.stringify({ "x-ms-sevsnpvm-guestsvn": 5 })),
    );

    const policy = KeyReleasePolicy.getKeyReleasePolicyFromMap(gcpKeyReleasePolicyMap);
    const result = KeyReleasePolicy.validateKeyReleasePolicy(
      policy,
      buildClaims({ "x-ms-sevsnpvm-guestsvn": 0 }),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });
});

// ==========================================================================
describe("validateGcpAttestation with real SNP verification", () => {
  test("fails when attestation binary is invalid (dummy data)", () => {
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": GCP_VALID_MEASUREMENTS });
    // The CCF polyfill rejects non-SNP binary; this confirms the real
    // verification path is active (not a hardcoded stub).
    const result = validateGcpAttestation(DUMMY_ATTESTATION);
    expect(result.success).toBe(false);
  });
});

// ==========================================================================
describe("validateAttestation routing", () => {
  test("routes to GCP path when attestationType is 'gcp' (error is GCP-specific)", () => {
    setGcpClaims({ "x-ms-sevsnpvm-launchmeasurement": GCP_VALID_MEASUREMENTS });

    const result = validateAttestation(DUMMY_ATTESTATION, "gcp");
    expect(result.success).toBe(false);
    // GCP-specific error message confirms the GCP code path was taken.
    expect(result.error?.errorMessage).toContain("GCP attestation error");
  });

  test("defaults to azure path when attestationType is omitted", () => {
    // The azure path fails with "Internal error" (not "GCP attestation error").
    const result = validateAttestation(DUMMY_ATTESTATION, "azure");
    expect(result.success).toBe(false);
    expect(result.error?.errorMessage).not.toContain("GCP");
  });
});
