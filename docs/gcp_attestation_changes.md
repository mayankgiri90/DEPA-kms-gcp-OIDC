# GCP Attestation Support — Change Summary

**Branch:** `gcp_attest`
**Author:** vipulwalunj
**Last updated:** 2026-05-11

---

## Overview

Added support for GCP-based attestation alongside the existing Azure SNP attestation. Both platforms use AMD SEV-SNP hardware, so the binary verification mechanism (`snp_attestation.verifySnpAttestation`) is identical. The key differences are:

- Each cloud has its own independent **key release policy** (separate CCF KV map).
- The GCP policy must be seeded with the **vCPU-specific launch measurements** for GCP Confidential VMs (see `GCP_VCPU_MEASUREMENTS` below).

The same KMS endpoints (`/key`, `/unwrapKey`) serve both clouds. The caller identifies the cloud by adding `"attestationType": "gcp"` to the request body. Omitting the field defaults to `"azure"` — fully backward compatible.

---

## Architecture

```
POST /key  or  /unwrapKey
  └── request body: { attestation: {...}, attestationType: "azure" | "gcp" }
        │
        │  keyEndpoint.ts:137
        │  attestationProvider = body["attestationType"] || "azure"
        │
        │  keyEndpoint.ts:165
        │  validateAttestation(attestation, attestationProvider)
        │
        ├── attestationType === "azure"  (default)
        │     AttestationValidation.ts
        │     └── snp_attestation.verifySnpAttestation()  [CCF built-in]
        │           └── SnpAttestationClaims.getClaims()
        │                 └── KeyReleasePolicy → keyReleasePolicyMap  (Azure)
        │
        └── attestationType === "gcp"
              GcpAttestationValidation.ts
              └── snp_attestation.verifySnpAttestation()  [same CCF built-in]
                    └── SnpAttestationClaims.getClaims()
                          └── KeyReleasePolicy → gcpKeyReleasePolicyMap  (GCP)
                                x-ms-sevsnpvm-launchmeasurement ∈ GCP_VALID_MEASUREMENTS
```

Both paths produce the same `IAttestationReport` shape, so everything downstream (wrapping key hash check, key response) is unchanged.

---

## Files Changed

### Modified Files

#### `src/attestation/ISnpAttestation.ts`
Added `AttestationProvider` union type and optional `attestationType` field.

```typescript
export type AttestationProvider = "azure" | "gcp";

export interface ISnpAttestation {
  evidence: string;
  endorsements: string;
  uvm_endorsements: string;
  endorsed_tcb: string;
  attestationType?: AttestationProvider;  // NEW — defaults to "azure"
}
```

---

#### `src/repositories/Maps.ts`
Added a separate CCF KV map for the GCP key release policy, independent of the Azure map.

```typescript
export const gcpKeyReleaseMapName = "public:policies.gcp_key_release";
export const gcpKeyReleasePolicyMap = ccf.kv[gcpKeyReleaseMapName];
```

**Why separate maps?** Azure and GCP governance proposals are independent — different operators vote on each cloud's policy. A single shared map would couple their governance lifecycles.

---

#### `src/attestation/AttestationValidation.ts`
Added `attestationProvider` parameter (defaults to `"azure"`). Dispatches to `validateGcpAttestation` early; the entire existing Azure SNP path is untouched.

```typescript
export const validateAttestation = (
  attestation: ISnpAttestation,
  attestationProvider: AttestationProvider = "azure",
): ServiceResult<string | IAttestationReport> => {

  if (attestationProvider === "gcp") {
    return validateGcpAttestation(attestation);  // dispatches and returns
  }

  // ... existing Azure SNP flow unchanged ...
};
```

---

#### `src/endpoints/keyEndpoint.ts`
Added `attestationType?: AttestationProvider` to `IKeyRequest`. Both `key` and `unwrapKey` handlers read `attestationType` from the request body and pass it to `validateAttestation`.

```typescript
export interface IKeyRequest {
  attestation: ISnpAttestation;
  wrappingKey?: string;
  attestationType?: AttestationProvider;  // NEW
}

// inside key() and unwrapKey():
const attestationProvider: AttestationProvider =
  serviceRequest.body["attestationType"] || "azure";
```

---

#### `src/actions/actions.ts`
Registered the new `set_gcp_key_release_policy` governance action.

```typescript
import { action as gcpKeyReleasePolicyAction } from "./set_gcp_key_release_policy";

export const actions = new Map<string, Action>([
  settingsPolicyAction,
  keyReleasePolicyAction,
  gcpKeyReleasePolicyAction,  // NEW
  keyRotationPolicyAction,
  jwtValidationPolicyAction,
]);
```

---

#### `src/attestation/VtpmAttestation.ts`
Added two new exports alongside the existing `HARDCODED_GCP_VTPM_RESULT` test stub.

**`GCP_VCPU_MEASUREMENTS`** — AMD SEV-SNP `measurement` values for GCP Confidential VMs, keyed by vCPU count. These are the `x-ms-sevsnpvm-launchmeasurement` values to include in the GCP key release policy.

| vCPUs | Measurement (hex, 48 bytes / 96 chars) |
|------:|----------------------------------------|
| 1 | `9fee1c2d9279a6f330c728e17e5427685558604a141486dcb549da5b81c7492cdfd3fc4c1a3552bd9b6af65930b20641` |
| 2 | `7a5ed176bad8a9ff02cebb94b24b076a0b1905042a85d9fca7670d3a3ff466db3b1c2b76f8eca888f8d806d2ec92434e` |
| 4 | `ad532545a87f7ebba7ded856946f9f638d4395fe8ae6b82b694668774546fc4a5f3f7bf6eb389380743f39dffdf1bccc` |
| 8 | `0395ba843be8a2d2119eef812e562b9c26bcb1015fb465d448addd200dc90bb880f287ee367fddecedd89ce73162a62c` |
| 16 | `10f343779aa9a95ba781c9a39db9fde3ef611aeac8d2f516cc750f48a363a1bb67440dc8595e8dafa855326aa4356e4c` |
| 24 | `539a2d13373db75fd758219ec7c341ce9921b063d33efb88055f38bb4e4b7c3bf140d0a2589afa9292bfb6c7a787bafb` |
| 32 | `591b1103647089d793ffeaad653eaa2394972c09a4bc0178bf76b77860151b7b9c70856b0a36c4d421a74cf84a19944a` |
| 48 | `56df6081776e76d374152d5343060771f24acfdd75c3af4b360c91b9b26e43c2fab0a2157a5a746c929b2a342dbda54b` |
| 64 | `94cd8c643cf5ec38966b8243a908ddc2abea1b4922bd04d57ba0bb38df8f8f4ac7e6c70bad6d1672df81ccd2ee26605b` |
| 80 | `60ce03d7ee1a0fffcf3c865202371ba38856b6c1f2edcfb42ba0cc2e980d0eb15f18abd0450c34519ac73ca7c838855b` |
| 96 | `d4e07619f794b16a0e73ec742f947fdb773947082a5c506cf0fb1bfc63cb0aaa571eb792ad04e90d7601bc500373386e` |
| 112 | `182fe328f4abaccfde4b4041856a745577c22457018646eff585e1ba4c7179fa7b86abdb3d9f27d52b168ac924199bc3` |
| 128 | `ce64dfb5dcd3ad66bc488f5badb7b45b2374beb1f3926ea96fd59b62ac77ee9a802f7432ea6607d5772e166812d6a638` |

**`GCP_VALID_MEASUREMENTS`** — flat array of all 13 measurement strings; convenience export for populating the governance proposal.

```typescript
export const GCP_VALID_MEASUREMENTS: string[] = Object.values(GCP_VCPU_MEASUREMENTS);
```

---

### New Files

#### `src/attestation/GcpAttestationValidation.ts`
Validates a GCP Confidential VM SNP attestation against the GCP key release policy. The verification flow is identical to the Azure path — using the same CCF built-in `snp_attestation.verifySnpAttestation()` — but claims are validated against `gcpKeyReleasePolicyMap`.

**Flow:**
1. Validate and base64-decode `evidence`, `endorsements`, `uvm_endorsements`
2. Call `snp_attestation.verifySnpAttestation(evidence, endorsements, uvm_endorsements, endorsed_tcb)`
3. Extract claims via `SnpAttestationClaims.getClaims()` — produces `x-ms-sevsnpvm-launchmeasurement` and other standard SNP claims
4. Load GCP key release policy from `gcpKeyReleasePolicyMap`
5. Run `KeyReleasePolicy.validateKeyReleasePolicy(policy, claims)`
6. Return pass/fail `ServiceResult`

Errors are prefixed with `"GCP attestation error: ..."` (vs `"Internal error: ..."` on the Azure path) to make routing distinguishable in logs and tests.

---

#### `src/actions/set_gcp_key_release_policy.js`
CCF governance action for managing the GCP key release policy. Mirrors `set_key_release_policy.js` but writes to `gcpKeyReleaseMapName` (`public:policies.gcp_key_release`).

Supports the same operations as the Azure action:

| Operation | Description |
|-----------|-------------|
| `add` + `claims` | Add equality-check claim values |
| `remove` + `claims` | Remove equality-check claim values |
| `add` + `gte` / `gt` | Add numeric threshold claims |
| `remove` + `gte` / `gt` | Remove numeric threshold claims |

**Example governance proposal — seed all GCP measurements:**
```json
{
  "actions": [{
    "name": "set_gcp_key_release_policy",
    "args": {
      "type": "add",
      "claims": {
        "x-ms-sevsnpvm-launchmeasurement": [
          "9fee1c2d9279a6f330c728e17e5427685558604a141486dcb549da5b81c7492cdfd3fc4c1a3552bd9b6af65930b20641",
          "7a5ed176bad8a9ff02cebb94b24b076a0b1905042a85d9fca7670d3a3ff466db3b1c2b76f8eca888f8d806d2ec92434e",
          "ad532545a87f7ebba7ded856946f9f638d4395fe8ae6b82b694668774546fc4a5f3f7bf6eb389380743f39dffdf1bccc",
          "0395ba843be8a2d2119eef812e562b9c26bcb1015fb465d448addd200dc90bb880f287ee367fddecedd89ce73162a62c",
          "10f343779aa9a95ba781c9a39db9fde3ef611aeac8d2f516cc750f48a363a1bb67440dc8595e8dafa855326aa4356e4c",
          "539a2d13373db75fd758219ec7c341ce9921b063d33efb88055f38bb4e4b7c3bf140d0a2589afa9292bfb6c7a787bafb",
          "591b1103647089d793ffeaad653eaa2394972c09a4bc0178bf76b77860151b7b9c70856b0a36c4d421a74cf84a19944a",
          "56df6081776e76d374152d5343060771f24acfdd75c3af4b360c91b9b26e43c2fab0a2157a5a746c929b2a342dbda54b",
          "94cd8c643cf5ec38966b8243a908ddc2abea1b4922bd04d57ba0bb38df8f8f4ac7e6c70bad6d1672df81ccd2ee26605b",
          "60ce03d7ee1a0fffcf3c865202371ba38856b6c1f2edcfb42ba0cc2e980d0eb15f18abd0450c34519ac73ca7c838855b",
          "d4e07619f794b16a0e73ec742f947fdb773947082a5c506cf0fb1bfc63cb0aaa571eb792ad04e90d7601bc500373386e",
          "182fe328f4abaccfde4b4041856a745577c22457018646eff585e1ba4c7179fa7b86abdb3d9f27d52b168ac924199bc3",
          "ce64dfb5dcd3ad66bc488f5badb7b45b2374beb1f3926ea96fd59b62ac77ee9a802f7432ea6607d5772e166812d6a638"
        ]
      }
    }
  }]
}
```

---

#### `test/unit-test/attestation/GcpAttestation.test.ts`
25 unit tests covering the GCP attestation path. Uses the CCF polyfill for in-memory KV store.

| Test group | Count | What is tested |
|---|---|---|
| `HARDCODED_GCP_VTPM_RESULT` structure | 4 | Field values, ArrayBuffer sizes, UVM endorsement strings |
| `SnpAttestationClaims` extraction | 6 | Version, booleans, hex-encoded ArrayBuffers, UVM fields |
| `GCP_VCPU_MEASUREMENTS` | 6 | Entry count, hex format, uniqueness, spot-checks for 1 and 128 vCPUs |
| GCP policy validation (via `KeyReleasePolicy` directly) | 6 | Measurement pass/fail, full-table allowlist, missing claims, `gte` operator |
| `validateGcpAttestation` with real SNP | 1 | Confirms real verification path is active (dummy binary fails) |
| `validateAttestation` routing | 2 | GCP error prefix confirms GCP path; Azure path confirmed by absence of "GCP" |

**All 64 tests pass** (25 GCP + 39 pre-existing).

> **Note on policy test approach:** Policy logic tests call `KeyReleasePolicy` directly rather than going through `validateGcpAttestation`, because real SNP binary verification requires actual hardware or a signed attestation report. This cleanly separates policy correctness from binary verification.

---

## How to Use

### Client Request (GCP)
Add `"attestationType": "gcp"` to the request body for `/key` or `/unwrapKey`:

```json
{
  "attestationType": "gcp",
  "attestation": {
    "evidence": "<base64-encoded SNP attestation report>",
    "endorsements": "<base64-encoded VCEK certificate chain>",
    "uvm_endorsements": "<base64-encoded UVM endorsements>",
    "endorsed_tcb": "<TCB version string>"
  }
}
```

### Setting Up the GCP Key Release Policy
Submit a CCF governance proposal using the `set_gcp_key_release_policy` action. At minimum, include `x-ms-sevsnpvm-launchmeasurement` with the measurements for all vCPU counts your environment uses (see the example proposal above for all 13 values).

To restrict to a specific vCPU count (e.g., only 8-vCPU VMs):
```json
{
  "actions": [{
    "name": "set_gcp_key_release_policy",
    "args": {
      "type": "add",
      "claims": {
        "x-ms-sevsnpvm-launchmeasurement": [
          "0395ba843be8a2d2119eef812e562b9c26bcb1015fb465d448addd200dc90bb880f287ee367fddecedd89ce73162a62c"
        ]
      }
    }
  }]
}
```

### Azure Callers (No Change Required)
Existing callers without `attestationType` continue to work exactly as before — the field defaults to `"azure"`.

---

## What Remains (TODOs)

| Item | Location |
|---|---|
| Determine actual GCP UVM endorsement `did` and `feed` values for real environments | `src/attestation/VtpmAttestation.ts` |
| Submit GCP key release policy governance proposal for each deployed environment | Ops / governance |
| Add system/e2e tests for the GCP attestation path using real GCP attestation samples | `test/system-test/` |
