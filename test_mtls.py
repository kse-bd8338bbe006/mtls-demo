#!/usr/bin/env python3
import base64
import hashlib
import json
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode

KC_URL = "https://keycloak.192.168.50.10.nip.io"
REALM = "api-security"
CLIENT_ID = "mtls-demo"
TOKEN_ENDPOINT = f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token"

CERT_DIR = Path(__file__).resolve().parent / "certs"
CLIENT_CERT = CERT_DIR / "client.crt"
CLIENT_KEY = CERT_DIR / "client.key"
WRONG_CERT = CERT_DIR / "wrong.crt"
WRONG_KEY = CERT_DIR / "wrong.key"

passed = 0
failed = 0


def print_result(name, ok, detail=""):
    global passed, failed
    if ok:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}" + (f" ({detail})" if detail else ""))
        failed += 1


def make_ssl_context(cert_path=None, key_path=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert_path and key_path:
        ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def token_request(cert_path=None, key_path=None):
    ctx = make_ssl_context(cert_path, key_path)
    data = urlencode({"grant_type": "client_credentials", "client_id": CLIENT_ID}).encode()
    req = Request(TOKEN_ENDPOINT, data=data, method="POST")
    try:
        with urlopen(req, context=ctx) as resp:
            return resp.status, json.loads(resp.read())
    except Exception as e:
        code = getattr(e, "code", None)
        body = None
        if hasattr(e, "read"):
            try:
                body = json.loads(e.read())
            except Exception:
                pass
        return code, body


def decode_jwt_payload(token):
    payload_b64 = token.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def cert_thumbprint(cert_path):
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# --- Test 1: valid client certificate ---
print("\n=== Test 1: Token request with valid client certificate ===")
status, body = token_request(CLIENT_CERT, CLIENT_KEY)
print_result("Returns 200", status == 200, f"got {status}")

access_token = body.get("access_token", "") if body else ""
if not access_token:
    print_result("Response contains access_token", False)
else:
    print(f"  Access token received ({len(access_token)} chars)")

# --- Test 2: cnf claim with x5t#S256 ---
print("\n=== Test 2: Verify cnf claim in access token ===")
if access_token:
    payload = decode_jwt_payload(access_token)
    print(json.dumps(payload, indent=2))

    token_thumbprint = payload.get("cnf", {}).get("x5t#S256", "")
    expected_thumbprint = cert_thumbprint(CLIENT_CERT)

    print_result(
        "cnf thumbprint matches certificate",
        token_thumbprint == expected_thumbprint,
        f"token={token_thumbprint}, cert={expected_thumbprint}",
    )
    print(f"  Thumbprint: {token_thumbprint}")
else:
    print_result("cnf claim present", False, "no access token")

# --- Test 3: request without certificate ---
print("\n=== Test 3: Token request without client certificate ===")
status, _ = token_request()
print_result("Returns 401", status == 401, f"got {status}")

# --- Test 4: request with wrong certificate ---
print("\n=== Test 4: Token request with wrong client certificate ===")
status, _ = token_request(WRONG_CERT, WRONG_KEY)
print_result("Returns 401", status == 401, f"got {status}")

# --- Summary ---
print(f"\n=== Results: {passed} passed, {failed} failed ===")
sys.exit(0 if failed == 0 else 1)
