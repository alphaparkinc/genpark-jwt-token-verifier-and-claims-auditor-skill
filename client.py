"""JWT Token Verifier & Claims Auditor.
100% Python Standard Library.
"""
import json
import base64
import time

class JwtTokenClaimsAuditor:
    """Pure-Python zero-dependency JWT claims auditor and payload inspector."""

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        rem = len(data) % 4
        if rem > 0:
            data += "=" * (4 - rem)
        return base64.urlsafe_b64decode(data)

    @classmethod
    def audit_token(cls, token: str, expected_issuer: str = None, expected_audience: str = None, current_time: float = None) -> dict:
        now = current_time or time.time()
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"is_valid": False, "error": "Invalid JWT format: expected 3 dot-separated segments"}

        try:
            header_json = cls._b64_decode(parts[0]).decode("utf-8")
            header = json.loads(header_json)
        except Exception as e:
            return {"is_valid": False, "error": f"Failed to decode header: {e}"}

        try:
            payload_json = cls._b64_decode(parts[1]).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception as e:
            return {"is_valid": False, "error": f"Failed to decode payload: {e}"}

        violations = []
        alg = header.get("alg", "").upper()
        if alg == "NONE":
            violations.append("Insecure algorithm: 'none' algorithm is prohibited")

        exp = payload.get("exp")
        if exp is not None:
            if now > exp:
                violations.append(f"Token expired: exp={exp}, current_time={int(now)}")

        nbf = payload.get("nbf")
        if nbf is not None:
            if now < nbf:
                violations.append(f"Token not yet valid: nbf={nbf}, current_time={int(now)}")

        if expected_issuer and payload.get("iss") != expected_issuer:
            violations.append(f"Issuer mismatch: expected '{expected_issuer}', got '{payload.get('iss')}'")

        if expected_audience:
            aud = payload.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud or [])
            if expected_audience not in aud_list:
                violations.append(f"Audience mismatch: expected '{expected_audience}', got '{aud}'")

        return {
            "is_valid": len(violations) == 0,
            "header": header,
            "payload": payload,
            "violations": violations,
            "signature_present": len(parts[2]) > 0
        }
