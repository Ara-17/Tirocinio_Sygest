<#
.SYNOPSIS
    Script di automazione scansione Aqua Trivy Multi-Disco e invio a Sygest API.
.DESCRIPTION
    1. Trova dinamicamente tutti i dischi rigidi locali (C:\, D:\, ecc.)
    2. Lancia la scansione del File System con Trivy su ogni disco
    3. Fonde i risultati in un unico grande JSON unificato
    4. Invia il JSON via REST API e pulisce i file temporanei
#>

# - CONFIGURAZIONE VARIABILI -
# Il nome dell'host viene ora letto dinamicamente dal sistema operativo (es. SRV-WIN-01)
$TargetHostname = $env:COMPUTERNAME

# Configurazione API (NOTA: la porta esterna di Docker è la 5001)
$ApiUrl = "http://192.168.110.60:5001/api/v1/trivy"
$ApiKey = "TEST"

# Trova in automatico la cartella temporanea di sistema sicura
$SystemDrive  = $env:SystemDrive
$TrivyExePath = "$SystemDrive\Windows\Temp\trivy.exe"
$FinalReport  = "$SystemDrive\Windows\Temp\trivy_report_finale.json"

# - RICERCA DISCHI E CONTROLLI -
if (-not (Test-Path $TrivyExePath)) {
    Write-Error "ERRORE: Eseguibile di Trivy non trovato in $TrivyExePath"
    exit
}

# Rileva tutti i dischi locali (DriveType=3 evita le chiavette USB e i dischi di rete)
$DrivesToScan = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3").DeviceID | ForEach-Object { "$_\" }

Write-Host "Dischi locali rilevati pronti per la scansione: $($DrivesToScan -join ', ')"

# - ESECUZIONE MULTI-DISCO E MERGE JSON -
$BaseJson = $null
$AllResults = @()

foreach ($Drive in $DrivesToScan) {
    Write-Host "Avvio scansione Trivy sul disco $Drive..."
    
    # Creo un nome file temporaneo basato sulla lettera del disco (es. trivy_temp_C.json)
    $TempReport = "$SystemDrive\Windows\Temp\trivy_temp_$($Drive.Replace(':\','')).json"
    if (Test-Path $TempReport) { Remove-Item $TempReport -Force }

    # Lancio Trivy silenziato
    $TrivyArgs = "fs $Drive --scanners vuln --format json -o $TempReport"
    $Process = Start-Process -FilePath $TrivyExePath -ArgumentList $TrivyArgs -Wait -NoNewWindow -PassThru

    if (Test-Path $TempReport) {
        Write-Host "Scansione completata per $Drive. Elaborazione dati in corso..."
        
        # Leggo il JSON generato per questo specifico disco
        $ScanData = Get-Content -Path $TempReport -Raw | ConvertFrom-Json
        
        # Uso il primo JSON trovato come base per mantenere intestazioni e metadata
        if ($null -eq $BaseJson) {
            $BaseJson = $ScanData
        }
        
        # Se Trivy ha trovato delle vulnerabilità, estraggo l'array 'Results' e lo unisco alla lista globale
        if ($null -ne $ScanData.Results) {
            $AllResults += $ScanData.Results
        }
        
        # Pulisco il file temporaneo del singolo disco
        Remove-Item $TempReport -Force
    } else {
        Write-Warning "Nessun report generato per il disco $Drive."
    }
}

# Ricostruisco il JSON unificato inserendo tutte le vulnerabilità di tutti i dischi
if ($null -ne $BaseJson) {
    Write-Host "Generazione del report unificato in corso..."
    $BaseJson.Results = $AllResults
    
    # Salvo il file finale. Il parametro '-Depth 100' in PowerShell permette di non troncare/corrompere i JSON complessi
    $BaseJson | ConvertTo-Json -Depth 100 -Compress | Set-Content -Path $FinalReport
} else {
    Write-Error "ERRORE CRITICO: Impossibile generare il JSON unificato. Trivy ha fallito su tutti i dischi."
    exit
}

# - INVIO DATI ALL'API -
if (Test-Path $FinalReport) {
    Write-Host "Preparazione invio API per l'host: $TargetHostname..."
    
    $Headers = @{
        "X-API-Key" = $ApiKey
    }
    
    try {
        # Eseguo la chiamata POST inviando il JSON unificato
        $Response = Invoke-RestMethod -Uri $ApiUrl `
                                      -Method Post `
                                      -Headers $Headers `
                                      -Form @{
                                          hostname = $TargetHostname
                                          file     = Get-Item -Path $FinalReport
                                      }
                                      
        Write-Host "Report inviato con successo all'API Sygest!"
        
        # Pulizia finale sul disco Temp del server Windows
        Remove-Item $FinalReport -Force
        Write-Host "File temporaneo finale eliminato."
        
    } catch {
        Write-Error "ERRORE durante l'invio all'API: $_"
    }
}