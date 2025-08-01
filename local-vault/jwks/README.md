Local JWKS Server (for RS256 tests)

Overview
- Serves a static `jwks.json` over HTTP for local RS256/JWKS token verification.
- Runs as an `nginx:alpine` container exposed at `http://127.0.0.1:9001/jwks.json`.

Usage
1) Generate JWKS (and optionally a test token):
   - `python scripts/gen_rsa_jwks.py --out local-vault/jwks --kid demo --issuer mcp-auth --audience mcp-agents --sub agent_jwt --scopes read,write,delete,list --ttl 300 --emit-token`
   - Files:
     - `local-vault/jwks/jwks.json` (public keys served by nginx)
     - `local-vault/jwks/private.pem` (private key for signing, not exposed)
   - The script prints a signed RS256 JWT to stdout; save it to `TOK` to test.

2) Start the JWKS server:
   - From `local-vault/`: `docker compose up -d jwks`
   - Verify: `curl http://127.0.0.1:9001/jwks.json`

3) Configure the MCP server to use JWKS:
   - `export AUTH_JWT_ENABLED=true`
   - `export JWT_ISSUER=mcp-auth`
   - `export JWT_AUDIENCE=mcp-agents`
   - `export JWT_JWKS_URL=http://127.0.0.1:9001/jwks.json`
   - Start server (e.g., `bash scripts/run_all_auth.sh`)

4) Test with the RS256 token:
   - `curl -H "Authorization: Bearer $TOK" http://127.0.0.1:8089/whoami`
   - Or run: `bash scripts/test_agent_jwt_rs256.sh`

Notes
- To rotate keys, regenerate with a new `--kid` and update `jwks.json` to include both keys during the transition.
- The JWKS server is static; it only serves whatever is in this folder.

