$Target = "192.168.50.20"
$Username = "threatlens-test"
$Attempts = 7

Write-Host ""
Write-Host "======================================"
Write-Host " ThreatLens SSH Authentication Demo"
Write-Host "======================================"
Write-Host "Target:   $Target"
Write-Host "Username: $Username"
Write-Host "Attempts: $Attempts"
Write-Host ""

for ($i = 1; $i -le $Attempts; $i++) {

    Write-Host "[*] Attempt $i/$Attempts"

    ssh `
        -o StrictHostKeyChecking=no `
        -o UserKnownHostsFile=NUL `
        -o ConnectTimeout=3 `
        -o NumberOfPasswordPrompts=1 `
        "$Username@$Target" exit

    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "[+] Demo completed."
Write-Host "[+] $Attempts SSH authentication attempts generated."