#!/bin/bash
# HoneyKey Demo Test Script
# Run: bash test_demo.sh

BASE_URL="http://localhost:8000"
KEY="${HONEYPOT_KEY:-acme_live_f93k2jf92jf0s9df}"

echo "=== HoneyKey Demo Tests ==="
echo "Key: $KEY"

echo -e "\n[1] Simulating attacker..."
for ep in /v1/projects /v1/secrets /v1/auth/verify; do
    curl -s -X GET "$BASE_URL$ep" -H "Authorization: Bearer $KEY" > /dev/null
    echo "  Hit $ep"
    sleep 0.3
done

echo -e "\n[2] Incidents:"
curl -s "$BASE_URL/incidents" | python -m json.tool 2>/dev/null || curl -s "$BASE_URL/incidents"

echo -e "\n[3] Block status for incident 1:"
curl -s "$BASE_URL/incidents/1/block-status"

echo -e "\n[4] Block IP:"
curl -s -X POST "$BASE_URL/incidents/1/block-ip" -H "Content-Type: application/json" -d '{"duration_hours":1}'

echo -e "\n[5] Test blocked (expect 401):"
curl -s "$BASE_URL/v1/projects" -H "Authorization: Bearer $KEY"

echo -e "\n[6] Unblock:"
curl -s -X DELETE "$BASE_URL/incidents/1/unblock-ip"

echo -e "\n[7] Blocklist:"
curl -s "$BASE_URL/blocklist"

echo -e "\n=== Done ==="
