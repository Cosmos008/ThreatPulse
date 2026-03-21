param(
    [string]$ApiKey,
    [string]$BaseIp = "10.10.10",
    [string]$GeolocationTestIp = "8.8.8.8",
    [int]$FailedAttempts = 11
)

$ErrorActionPreference = "Stop"

function Get-EnvValue {
    param(
        [string]$Name,
        [string]$DefaultValue
    )

    if (Test-Path ".env") {
        $line = Get-Content ".env" | Where-Object { $_ -match "^${Name}=" } | Select-Object -First 1
        if ($line) {
            return ($line -split "=", 2)[1].Trim()
        }
    }

    return $DefaultValue
}

if (-not $ApiKey) {
    $ApiKey = Get-EnvValue -Name "SECURITY_API_KEY" -DefaultValue "change-this-api-key"
}

$postgresUser = Get-EnvValue -Name "POSTGRES_USER" -DefaultValue "security"
$postgresDb = Get-EnvValue -Name "POSTGRES_DB" -DefaultValue "alerts"
$testSuffix = Get-Random -Minimum 1000 -Maximum 9999
$testIp = "$BaseIp.$($testSuffix % 250 + 1)"
$headers = @{ "X-API-Key" = $ApiKey }
$body = @{
    event_type = "login_attempt"
    user_id = "smoke-user-$testSuffix"
    ip = $testIp
    device_id = "smoke-device-$testSuffix"
    status = "failed"
} | ConvertTo-Json -Compress

Write-Host "Checking health endpoints..."
$ingestionHealth = Invoke-RestMethod -Uri "http://localhost:8000/health"
$investigationHealth = Invoke-RestMethod -Uri "http://localhost:8001/health"
$geolocationHealth = Invoke-RestMethod -Uri "http://localhost:8002/health"

Write-Host "Ingestion health: $($ingestionHealth | ConvertTo-Json -Compress)"
Write-Host "Investigation health: $($investigationHealth | ConvertTo-Json -Compress)"
Write-Host "Geolocation health: $($geolocationHealth | ConvertTo-Json -Compress)"

Write-Host "Sending $FailedAttempts failed login events for IP $testIp ..."
1..$FailedAttempts | ForEach-Object {
    Invoke-RestMethod -Method Post -Uri "http://localhost:8000/log" -Headers $headers -ContentType "application/json" -Body $body | Out-Null
}

Start-Sleep -Seconds 5

Write-Host "Querying investigation API..."
$apiResult = Invoke-RestMethod -Uri "http://localhost:8001/alerts/ip/$testIp" -Headers $headers
$apiJson = $apiResult | ConvertTo-Json -Depth 8
Write-Host $apiJson

Write-Host "Querying geolocation API..."
$geoBody = @{ ips = @($GeolocationTestIp, $testIp) } | ConvertTo-Json -Compress
$geoResult = Invoke-RestMethod -Method Post -Uri "http://localhost:8002/lookup" -Headers $headers -ContentType "application/json" -Body $geoBody
$geoJson = $geoResult | ConvertTo-Json -Depth 8
Write-Host $geoJson

Write-Host "Querying Postgres..."
$sql = "SELECT id, rule, severity, ip FROM alerts WHERE ip = '$testIp' ORDER BY id DESC LIMIT 10;"
$dbResult = docker exec postgres psql -U $postgresUser -d $postgresDb -c $sql
$dbResult | ForEach-Object { Write-Host $_ }
$dbText = ($dbResult -join "`n")

if (-not $apiResult.alerts -or $apiResult.alerts.Count -lt 1) {
    throw "Smoke test failed: no alerts returned by investigation API for $testIp"
}

if ($dbText -notmatch [regex]::Escape($testIp)) {
    throw "Smoke test failed: no alert row found in Postgres for $testIp"
}

$publicGeoResult = $geoResult.results | Where-Object { $_.ip -eq $GeolocationTestIp } | Select-Object -First 1
if (-not $publicGeoResult -or -not $publicGeoResult.found) {
    throw "Smoke test failed: geolocation lookup did not resolve public IP $GeolocationTestIp"
}

Write-Host "Smoke test passed for IP $testIp"
