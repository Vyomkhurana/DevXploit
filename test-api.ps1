Write-Host "🚀 Testing DevXploit API with improved vulnerability detection" -ForegroundColor Green
Write-Host ""

# Test scan
$response = Invoke-RestMethod -Uri "http://localhost:3000/api/scan" -Method POST -ContentType "application/json" -Body '{"url":"http://testphp.vulnweb.com","scanType":"comprehensive"}'
Write-Host "✅ Scan started successfully!" -ForegroundColor Green
Write-Host "📋 Scan ID: $($response.scanId)" -ForegroundColor Yellow
Write-Host "🔗 Status URL: $($response.statusUrl)" -ForegroundColor Cyan
Write-Host ""

# Wait for scan to complete
Write-Host "⏳ Waiting for scan to complete..." -ForegroundColor Yellow
$scanId = $response.scanId
$maxAttempts = 20
$attempt = 0

do {
    Start-Sleep 3
    $attempt++
    $statusResponse = Invoke-RestMethod -Uri "http://localhost:3000/api/scan/$scanId" -Method GET
    Write-Host "📊 Attempt $attempt - Status: $($statusResponse.status) - Progress: $($statusResponse.progress)%" -ForegroundColor Cyan
    
    if ($statusResponse.currentStep) {
        Write-Host "🔄 Current Step: $($statusResponse.currentStep)" -ForegroundColor Magenta
    }
    
} while ($statusResponse.status -eq "running" -and $attempt -lt $maxAttempts)

Write-Host ""
if ($statusResponse.status -eq "completed") {
    Write-Host "🎉 Scan completed successfully!" -ForegroundColor Green
    Write-Host "🚨 Vulnerabilities found: $($statusResponse.results.vulnerabilities.Count)" -ForegroundColor Red
    
    if ($statusResponse.results.vulnerabilities.Count -gt 0) {
        Write-Host "`n🔍 Vulnerabilities detected:" -ForegroundColor Red
        foreach ($vuln in $statusResponse.results.vulnerabilities) {
            Write-Host "  • [$($vuln.severity)] $($vuln.type): $($vuln.description)" -ForegroundColor Yellow
        }
    }
    
    if ($statusResponse.aiAnalysis) {
        Write-Host "`n🤖 AI Analysis Available:" -ForegroundColor Green
        Write-Host "  🔴 Red Team: $($statusResponse.aiAnalysis.redTeam.attackNarrative)" -ForegroundColor Red
        Write-Host "  🔵 Blue Team: $($statusResponse.aiAnalysis.blueTeam.defenseStrategy)" -ForegroundColor Blue
    }
} else {
    Write-Host "❌ Scan failed or timed out. Status: $($statusResponse.status)" -ForegroundColor Red
    if ($statusResponse.error) {
        Write-Host "Error: $($statusResponse.error)" -ForegroundColor Red
    }
}