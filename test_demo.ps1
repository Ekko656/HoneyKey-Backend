# HoneyKey Demo Test Script
# Run: .\test_demo.ps1

$BASE_URL = "http://localhost:8000"
$HONEYPOT_KEY = $env:HONEYPOT_KEY
if (-not $HONEYPOT_KEY) { $HONEYPOT_KEY = "acme_live_f93k2jf92jf0s9df" }

Write-Host "=== HoneyKey Demo Tests ===" -ForegroundColor Cyan
Write-Host "Using key: $HONEYPOT_KEY"

# Test 1: Simulate attacker probing multiple endpoints
Write-Host "`n[1] Simulating attacker reconnaissance..." -ForegroundColor Yellow
$endpoints = @("/v1/projects", "/v1/secrets", "/v1/auth/verify", "/v1/users", "/v1/admin")
foreach ($ep in $endpoints) {
    $r = curl.exe -s -X GET "$BASE_URL$ep" -H "Authorization: Bearer $HONEYPOT_KEY"
    Write-Host "  $ep -> Got response"
    Start-Sleep -Milliseconds 500
}

# Test 2: List incidents
Write-Host "`n[2] Checking incidents created..." -ForegroundColor Yellow
$incidents = curl.exe -s "$BASE_URL/incidents" | ConvertFrom-Json
Write-Host "  Total incidents: $($incidents.Count)"
if ($incidents.Count -gt 0) {
    $latest = $incidents[0]
    Write-Host "  Latest: ID=$($latest.id), IP=$($latest.source_ip), Events=$($latest.event_count)"
}

# Test 3: Generate AI report for latest incident
if ($incidents.Count -gt 0) {
    $incidentId = $incidents[0].id
    Write-Host "`n[3] Generating AI report for incident $incidentId..." -ForegroundColor Yellow
    $report = curl.exe -s -X POST "$BASE_URL/incidents/$incidentId/analyze"
    Write-Host $report
}

# Test 4: Check block status
if ($incidents.Count -gt 0) {
    $incidentId = $incidents[0].id
    Write-Host "`n[4] Checking block status..." -ForegroundColor Yellow
    $status = curl.exe -s "$BASE_URL/incidents/$incidentId/block-status"
    Write-Host "  $status"
}

# Test 5: Block the IP
if ($incidents.Count -gt 0) {
    $incidentId = $incidents[0].id
    Write-Host "`n[5] Blocking IP from incident..." -ForegroundColor Yellow
    $block = curl.exe -s -X POST "$BASE_URL/incidents/$incidentId/block-ip" -H "Content-Type: application/json" -d '{"duration_hours": 1, "notes": "Demo block"}'
    Write-Host "  $block"
}

# Test 6: Verify block works (should get 401)
Write-Host "`n[6] Testing if block works (expect 401)..." -ForegroundColor Yellow
$blocked = curl.exe -s "$BASE_URL/v1/projects" -H "Authorization: Bearer $HONEYPOT_KEY"
Write-Host "  Response: $blocked"

# Test 7: Unblock
if ($incidents.Count -gt 0) {
    $incidentId = $incidents[0].id
    Write-Host "`n[7] Unblocking IP..." -ForegroundColor Yellow
    $unblock = curl.exe -s -X DELETE "$BASE_URL/incidents/$incidentId/unblock-ip"
    Write-Host "  $unblock"
}

# Test 8: List blocklist
Write-Host "`n[8] Current blocklist:" -ForegroundColor Yellow
$blocklist = curl.exe -s "$BASE_URL/blocklist"
Write-Host "  $blocklist"

Write-Host "`n=== Done ===" -ForegroundColor Green
