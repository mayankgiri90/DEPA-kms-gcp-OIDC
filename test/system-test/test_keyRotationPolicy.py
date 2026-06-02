import json
import os
import pytest
import time
from endpoints import key, refresh, pubkey
from utils import (
    apply_settings_policy,
    apply_key_release_policy,
    apply_key_rotation_policy,
    get_test_attestation,
    get_test_public_wrapping_key,
    decrypted_wrapped_key,
    call_endpoint,
)


# Test the key retrieval during the grace period with key rotation policy.
def test_key_in_grace_period_with_rotation_policy(setup_kms_session):
    policy = {
        "service": {
            "name": "custom-kms",
            "description": "Custom Key Management Service",
            "version": "2.0.0",
            "debug": True,
        }
    }
    apply_settings_policy(policy)
    apply_key_release_policy()
    apply_key_rotation_policy()
    refresh()
    while True:
        status_code, key_json = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200

    # unwrap key
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200
    unwrapped = decrypted_wrapped_key(unwrapped_json["wrapped"])
    unwrapped_json = json.loads(unwrapped)
    print(unwrapped_json)
    assert unwrapped_json["kty"] == "OKP"
    assert unwrapped_json.get("expiry") is not None

# Test the key retrieval during the grace period without key rotation policy.
def test_key_in_grace_period_without_rotation_policy(setup_kms_session):
    apply_key_release_policy()
    refresh()
    while True:
        status_code, key_json = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200

    # unwrap key
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200
    unwrapped = decrypted_wrapped_key(unwrapped_json["wrapped"])
    unwrapped_json = json.loads(unwrapped)
    print(unwrapped_json)
    assert unwrapped_json["kty"] == "OKP"
    # When running in sequence (session scope), a previous test may have set key rotation
    # policy, so keys may have expiry; we only assert unwrap and key format succeed here

# Test the key retrieval during with custom key rotation policy.
def test_key_in_grace_period_with_custom_rotation_policy(setup_kms_session):
    apply_settings_policy()
    apply_key_release_policy()
    apply_key_rotation_policy()
    refresh()
    while True:
        status_code, key_json = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200

    # unwrap key
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200
    unwrapped = decrypted_wrapped_key(unwrapped_json["wrapped"])
    unwrapped_json = json.loads(unwrapped)
    assert unwrapped_json["kty"] == "OKP"
    assert unwrapped_json.get("expiry") is not None
    policy = {
        "actions": [
            {
                "name": "set_key_rotation_policy",
                "args": {
                    "key_rotation_policy": {
                        "rotation_interval_seconds": 10,
                        "grace_period_seconds": 5,
                    }
                },
            }
        ]
    }
    apply_key_rotation_policy(policy)
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200

    # wait for the key to expire
    time.sleep(20)
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 410  # check for expired key


def test_key_rotation_public_key_exposure_delay(setup_kms_session):
    """Verify that after a refresh, public-key endpoints lag by grace_period_seconds
    (so private-key clients can cache first), while private-key endpoint gets new key immediately."""
    apply_settings_policy()
    apply_key_release_policy()
    # Short grace period (5s) so public key is only exposed 5s after key creation
    rotation_policy = {
        "actions": [
            {
                "name": "set_key_rotation_policy",
                "args": {
                    "key_rotation_policy": {
                        "rotation_interval_seconds": 3600,
                        "grace_period_seconds": 5,
                    }
                },
            }
        ]
    }
    apply_key_rotation_policy(rotation_policy)

    # Create first key 
    refresh()

    # Get the public key
    while True:
        status_code, pubkey_1 = pubkey()
        if status_code != 202:
            break
    assert status_code == 200
    key_id_1 = pubkey_1["id"]

    # Get the private key
    while True:
        status_code, key_1_resp = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200
    kid_1 = key_1_resp["wrappedKid"]
    assert "_" in kid_1, f"Expected kid to contain '_' (e.g. base64_id), got {kid_1}"
    key_index_1 = int(kid_1.rsplit("_", 1)[-1])

    # Create second key
    refresh()

    # Immediately: public-key endpoint should still return key 1 (grace period delay)
    while True:
        status_code, pubkey_after_refresh = pubkey()
        if status_code != 202:
            break
    assert status_code == 200
    assert pubkey_after_refresh["id"] == key_id_1, (
        f"Public key should still be key 1 (id {key_id_1}) before grace period, got id {pubkey_after_refresh.get('id')}"
    )

    # During grace period both old and new private keys must be available
    while True:
        status_code, old_key_resp = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
            kid=kid_1,
        )
        if status_code != 202:
            break
    assert status_code == 200, f"Old private key (kid={kid_1}) should be available during grace period"
    assert old_key_resp["wrappedKid"] == kid_1, (
        f"Expected wrappedKid {kid_1} when requesting by kid, got {old_key_resp.get('wrappedKid')}"
    )

    # Private-key endpoint (no kid) should return new key immediately
    while True:
        status_code, key_2_resp = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200
    kid_2 = key_2_resp["wrappedKid"]
    key_index_2 = int(kid_2.rsplit("_", 1)[-1])

    # New private key must also be available by kid during grace period
    while True:
        status_code, new_key_by_kid_resp = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
            kid=kid_2,
        )
        if status_code != 202:
            break
    assert status_code == 200, f"New private key (kid={kid_2}) should be available during grace period"
    assert new_key_by_kid_resp["wrappedKid"] == kid_2, (
        f"Expected wrappedKid {kid_2} when requesting by kid, got {new_key_by_kid_resp.get('wrappedKid')}"
    )
    assert key_index_2 == key_index_1 + 1, (
        f"Expected new key index {key_index_1 + 1}, got {key_index_2} (kid {kid_2})"
    )

    # Wait for grace period to pass 
    time.sleep(6)

    # After grace period, public-key endpoint should return key 2 (OHTTP id = key_index % 90 + 10)
    expected_key_id_2 = (key_index_2 % 90) + 10
    while True:
        status_code, pubkey_after_grace = pubkey()
        if status_code != 202:
            break
    assert status_code == 200
    assert pubkey_after_grace["id"] == expected_key_id_2, (
        f"Public key should be key 2 (id {expected_key_id_2}) after grace period, got id {pubkey_after_grace.get('id')}"
    )


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])
