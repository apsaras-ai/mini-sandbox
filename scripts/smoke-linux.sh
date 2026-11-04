#!/usr/bin/env bash
set -euo pipefail
BASE="${MINI_SANDBOX_URL:-http://127.0.0.1:3000}"
curl -fsS "$BASE/readyz" >/dev/null
echo "Python:"
curl -fsS -H 'content-type: application/json' -d '{"language":"python","code":"print(1+1)"}' "$BASE/execute"
echo
echo "Node:"
curl -fsS -H 'content-type: application/json' -d '{"language":"node","code":"console.log(2+2)"}' "$BASE/execute"
echo
echo "Deadline:"
curl -fsS -H 'content-type: application/json' -d '{"language":"python","code":"while True: pass","timeout_ms":1000}' "$BASE/execute"
echo
echo "Networking must be disabled (expect a nonzero exit code):"
curl -fsS -H 'content-type: application/json' -d '{"language":"python","code":"import socket; socket.create_connection((\"1.1.1.1\", 80), 0.5)"}' "$BASE/execute"
echo
