"""MCP Server for JWT Token Verifier & Claims Auditor.
100% Python Standard Library JSON-RPC.
"""
import sys
import json
from client import JwtTokenClaimsAuditor

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")

            if method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [
                            {
                                "name": "audit_token",
                                "description": "Audit JWT token structure, signature presence, expiry, audience, and issuer",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "token": {"type": "string", "description": "JWT string"},
                                        "expected_issuer": {"type": "string"},
                                        "expected_audience": {"type": "string"}
                                    },
                                    "required": ["token"]
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                args = req.get("params", {}).get("arguments", {})
                res = JwtTokenClaimsAuditor.audit_token(
                    token=args.get("token", ""),
                    expected_issuer=args.get("expected_issuer"),
                    expected_audience=args.get("expected_audience")
                )
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
                }
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
