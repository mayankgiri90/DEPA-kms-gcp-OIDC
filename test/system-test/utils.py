import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
TEST_ENVIRONMENT = os.getenv("TEST_ENVIRONMENT", "ccf/sandbox_local")


def get_final_json(s):
    for sub in reversed(s.split("{")):
        try:
            return json.loads("{" + sub)
        except json.JSONDecodeError:
            ...


def deploy_app_code(**kwargs):
    subprocess.run(
        "scripts/kms/js_app_set.sh",
        cwd=REPO_ROOT,
        check=True,
        **kwargs,
    )


def call_endpoint(command):
    *response, status_code = subprocess.run(
        command,
        cwd=os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..")),
        stdout=subprocess.PIPE,
        shell=True,
    ).stdout.decode().splitlines()

    print(f'Called "{" ".join(command)}"')
    print(f"Response Code: {status_code}")
    print(f'Response Body: {json.loads("".join(response) or "{}")}')

    return (
        int(status_code),
        json.loads("".join(response) or '{}'),
    )


def apply_settings_policy(policy=None, get_logs=False):
    get_logs_arg = {"stdout": subprocess.PIPE} if get_logs else {}
    res = subprocess.run(
        "./scripts/kms/settings_policy_set.sh",
        env={
            **os.environ,
            **({"SETTINGS_POLICY": json.dumps(policy)} if policy is not None else {})
        },
        cwd=REPO_ROOT,
        check=True,
        **get_logs_arg,
    )

    # Parse out the returned json from the proposal
    if get_logs:
        return json.loads(
            "{" + "}".join(
                res.stdout.decode().split("{", 1)[1] # first open brace
                .split("}")[:-1] # last close brace
            ) + "}"
        )


def apply_key_release_policy():
    subprocess.run(
        [
            "scripts/kms/release_policy_set.sh",
            "governance/proposals/set_key_release_policy_add.json",
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def remove_key_release_policy():
    subprocess.run(
        [
            "scripts/kms/release_policy_set.sh",
            "governance/proposals/set_key_release_policy_remove.json",
        ],
        cwd=REPO_ROOT,
        check=True,
    )

def apply_key_rotation_policy(policy=None):
    command = [
        "scripts/kms/key_rotation_policy_set.sh",
        "governance/proposals/set_key_rotation_policy.json",
    ]
    env = {
        **os.environ,
        **({"ROTATION_POLICY": json.dumps(policy)} if policy is not None else {})
    }

    result = subprocess.run(
        command,
        env=env,
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        print("Error running key_rotation_policy_set.sh")
        print("stdout:", result.stdout.decode())
        print("stderr:", result.stderr.decode())
        result.check_returncode()  # This will raise the CalledProcessError

def trust_jwt_issuer(*args):
    subprocess.run(
        [
            "scripts/kms/jwt_issuer_trust.sh",
            *["--" + arg for arg in args],
        ],
        cwd=REPO_ROOT,
        check=True,
    )

def create_member(member_name):
    subprocess.run(
        ["scripts/ccf/member/create.sh", member_name],
        cwd=REPO_ROOT,
        check=True,
    )

def add_member(member_name):
    subprocess.run(
        ["scripts/ccf/member/add.sh", f"{os.getenv("WORKSPACE")}/{member_name}_cert.pem"],
        cwd=REPO_ROOT,
        check=True,
    )


def member_info(member_name):
    return json.loads(subprocess.run(
        ["scripts/ccf/member/info.sh", member_name],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE
    ).stdout.decode())


def use_member(member_name):
    env_vars = json.loads(subprocess.run(
        ["scripts/ccf/member/use.sh", member_name],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE
    ).stdout.decode())
    os.environ.update(env_vars)


def nodes_scale(node_count, get_logs=False):
    get_logs_arg = {"stdout": subprocess.PIPE} if get_logs else {}
    res = subprocess.run(
        [f"scripts/{TEST_ENVIRONMENT}/scale-nodes.sh", "-n", str(node_count)],
        cwd=REPO_ROOT,
        check=True,
        **get_logs_arg,
    )
    if get_logs:
        return get_final_json(res.stdout.decode())


def get_node_info(node_url):
    res = subprocess.run(
        [
            "curl",
            f"https://{node_url}/node/network/nodes/self",
            "--cacert", os.getenv("KMS_SERVICE_CERT_PATH"),
            "-w", "'\n%{http_code}'",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.decode()

    *response, status_code = res.strip("'").splitlines()
    return (
        int(status_code),
        json.loads("".join(response).strip("\'") or "{}"),
    )


def propose(proposal, get_logs=False):
    get_logs_arg = {"stdout": subprocess.PIPE} if get_logs else {}
    res = subprocess.run(
        ["scripts/ccf/propose.sh", proposal],
        cwd=REPO_ROOT,
        check=True,
        **get_logs_arg,
    )

    # Parse out the returned json from the proposal
    if get_logs:
        return json.loads("{" + res.stdout.decode().split("{", 1)[1])


def vote(proposal_id, vote, get_logs=False):
    get_logs_arg = {"stdout": subprocess.PIPE} if get_logs else {}
    res = subprocess.run(
        ["scripts/ccf/vote.sh", proposal_id, vote],
        cwd=REPO_ROOT,
        check=True,
        **get_logs_arg,
    )

    # Parse out the returned json from the proposal
    if get_logs:
        return json.loads("{" + res.stdout.decode().split("{", 1)[1])


# Path to attestation file used by unwrapKey tests (snp.json).
def get_test_attestation_file_path():
    return "test/attestation-samples/snp.json"


def get_test_attestation():
    path = os.path.join(REPO_ROOT, "test", "attestation-samples", "snp.json")
    with open(path, "r") as f:
        return f.read()

def get_test_public_wrapping_key():
    with open(os.path.join(os.path.dirname(__file__), '../data-samples/publicWrapKey.pem'), 'r') as file:
        key = file.read()
        # Escape newlines and wrap the key in double quotes
        key = key.replace("\n", "\\n")
        return f'"{key}"'

def get_test_private_wrapping_key():
    with open(os.path.join(os.path.dirname(__file__), '../data-samples/privateWrapKey.pem'), 'r') as file:
        key = file.read().strip()
        return key

def decrypted_wrapped_key(wrapped_key):
    # Load the private key from the PEM file
    private_key_data = get_test_private_wrapping_key()
    private_key = RSA.import_key(private_key_data)  # Convert PEM string to RSA key object
    print(f"Wrapped Key: {wrapped_key}, Length: {len(wrapped_key)}")

    # Initialize the cipher with the private key
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)

    # Decode the wrapped key from base64 and decrypt it
    wrapped_key = base64.b64decode(wrapped_key)
    print(f"Decoded Key Length: {len(wrapped_key)}")
    return cipher.decrypt(wrapped_key)


@contextmanager
def get_test_action():
    with tempfile.NamedTemporaryFile(mode="w+", prefix="test_action") as action_file:
        action_file.write("""
            actions.set(
                "test_action",
                new Action(function (args) {}, function (args) {}),
            );
        """)
        action_file.flush()
        yield action_file

@contextmanager
def get_test_proposal():
    with tempfile.NamedTemporaryFile(mode="w+", prefix="test_proposal") as proposal_file:
        proposal_file.write(json.dumps({
            "actions": [
                {
                    "name": "test_action",
                    "args": {}
                }
            ]
        }))
        proposal_file.flush()
        yield proposal_file