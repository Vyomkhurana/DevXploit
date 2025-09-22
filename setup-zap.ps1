# DevXploit OWASP ZAP Docker Setup Script (PowerShell)
# Usage: .\setup-zap.ps1 [start|stop|status|restart]

param(
    [string]$Action = "start"
)

Write-Host "🐳 DevXploit ZAP Docker Setup" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan

function Test-Docker {
    try {
        docker info | Out-Null
        Write-Host "✅ Docker is running" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Docker is not running. Please start Docker and try again." -ForegroundColor Red
        exit 1
    }
}

function Stop-ExistingZAP {
    Write-Host "🛑 Stopping any existing ZAP containers..." -ForegroundColor Yellow
    docker stop devxploit-zap 2>$null
    docker rm devxploit-zap 2>$null
    Write-Host "✅ Cleaned up existing containers" -ForegroundColor Green
}

function Start-ZAP {
    Write-Host "🚀 Starting OWASP ZAP Docker container..." -ForegroundColor Yellow
    
    $result = docker run -d `
        --name devxploit-zap `
        -p 8080:8080 `
        zaproxy/zap-stable `
        zap.sh -daemon -host 0.0.0.0 -port 8080 `
        -config api.addrs.addr.name=.* `
        -config api.addrs.addr.regex=true
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ ZAP container started successfully" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "❌ Failed to start ZAP container" -ForegroundColor Red
        exit 1
    }
}

function Wait-ForZAP {
    Write-Host "⏳ Waiting for ZAP to be ready..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le 30; $i++) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/JSON/core/view/version/" -TimeoutSec 2 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ ZAP is ready!" -ForegroundColor Green
                return $true
            }
        }
        catch {
            Write-Host "   Attempt $i/30 - waiting for ZAP to start..." -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
    }
    
    Write-Host "❌ ZAP failed to start within 60 seconds" -ForegroundColor Red
    exit 1
}

function Show-Status {
    Write-Host ""
    Write-Host "📊 ZAP Status:" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    
    $zapContainer = docker ps | Select-String "devxploit-zap"
    if ($zapContainer) {
        Write-Host $zapContainer -ForegroundColor Green
    }
    else {
        Write-Host "❌ ZAP container not running" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "🔗 ZAP API: http://localhost:8080" -ForegroundColor Blue
    Write-Host "🧪 Test: Invoke-WebRequest http://localhost:8080/JSON/core/view/version/" -ForegroundColor Blue
    Write-Host ""
}

# Main execution
switch ($Action.ToLower()) {
    "start" {
        Test-Docker
        Stop-ExistingZAP
        Start-ZAP
        Wait-ForZAP
        Show-Status
        Write-Host "🎉 DevXploit ZAP setup complete! You can now run: npm start" -ForegroundColor Green
    }
    
    "stop" {
        Write-Host "🛑 Stopping ZAP container..." -ForegroundColor Yellow
        docker stop devxploit-zap
        docker rm devxploit-zap
        Write-Host "✅ ZAP stopped and removed" -ForegroundColor Green
    }
    
    "status" {
        Write-Host "📊 ZAP Container Status:" -ForegroundColor Cyan
        $zapContainer = docker ps | Select-String "devxploit-zap"
        if ($zapContainer) {
            Write-Host $zapContainer -ForegroundColor Green
        }
        else {
            Write-Host "❌ ZAP container not running" -ForegroundColor Red
        }
        
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/JSON/core/view/version/" -TimeoutSec 5
            Write-Host "✅ ZAP API is responding" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ ZAP API not responding" -ForegroundColor Red
        }
    }
    
    "restart" {
        & $PSCommandPath -Action "stop"
        Start-Sleep -Seconds 2
        & $PSCommandPath -Action "start"
    }
    
    default {
        Write-Host "Usage: .\setup-zap.ps1 [start|stop|status|restart]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Commands:" -ForegroundColor Cyan
        Write-Host "  start   - Start ZAP Docker container" -ForegroundColor White
        Write-Host "  stop    - Stop and remove ZAP container" -ForegroundColor White
        Write-Host "  status  - Check ZAP container status" -ForegroundColor White
        Write-Host "  restart - Restart ZAP container" -ForegroundColor White
        exit 1
    }
}