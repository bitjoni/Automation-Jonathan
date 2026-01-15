# Relativ sökväg (från script-katalogen)
$ScriptDir = Split-Path -Parent $PSScriptRoot
$DataDir = Join-Path $ScriptDir "data"
$Output = Join-Path $DataDir "windows_services.csv"
$LogFile = Join-Path $DataDir "anomalies.log"

# Skapa data-mappen om den inte finns
if (-not (Test-Path $DataDir)) {
    try {
        New-Item -ItemType Directory -Path $DataDir | Out-Null
        Write-Host "Data-katalog skapad: $DataDir"
    }
    catch {
        Write-Error "Kunde inte skapa data-katalog: $_"
        exit 1
    }
}

# Hämta Windows-tjänster
try {
    $services = Get-Service | Select-Object Name, Status
    
    if ($services) {
        # Skriv till CSV
        $services | Export-Csv -NoTypeInformation -Path $Output -Force
        Write-Host "CSV skapad: $Output"
        
        # Logga anomalier
        $riskServices = @("Telnet", "RemoteRegistry", "Spooler")
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        foreach ($risk in $riskServices) {
            $found = $services | Where-Object { $_.Name -eq $risk }
            if ($found) {
                "[$timestamp] VARNING - Riskabel Windows-tjänst upptäckt: $risk" | Add-Content -Path $LogFile
                Write-Host "VARNING: Riskabel tjänst funnen - $risk"
            }
        }
    }
    else {
        Write-Warning "Inga tjänster hittades"
    }
}
catch {
    Write-Error "Fel vid hämtning av tjänster: $_"
    exit 1
}
