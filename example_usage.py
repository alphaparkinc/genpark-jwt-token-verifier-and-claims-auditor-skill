"""Example usage for JWT Token Verifier & Claims Auditor."""
from client import JwtTokenClaimsAuditor
import base64
import json
import time

now = time.time()
header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().strip("=")
payload = base64.urlsafe_b64encode(json.dumps({
    "sub": "agent_alpha",
    "iss": "https://genpark.ai",
    "aud": "genpark-cluster",
    "exp": int(now + 3600)
}).encode()).decode().strip("=")
token = f"{header}.{payload}.mock_sig"

res = JwtTokenClaimsAuditor.audit_token(token, expected_issuer="https://genpark.ai", expected_audience="genpark-cluster")
print(json.dumps(res, indent=2))
