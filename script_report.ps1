$headers = @{
    "X-API-Key" = "TEST"
}
Invoke-RestMethod -Uri "http://<IP_DEL_TUO_SERVER>:5000/api/v1/trivy" `
                  -Method Post `
                  -Headers $headers `
                  -Form @{
                      hostname = "spcb.sys-suite.com"
                      file = Get-Item -Path "C:\percorso\del\file\trivy_report.json"
                  }