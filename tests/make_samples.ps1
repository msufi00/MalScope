# tests/make_samples.ps1
# Creates safe test files in samples/ for MalScope (IKB31603, group GoodGuys).
# Run from the MalScope project root:   .\tests\make_samples.ps1
# No real malware is used. Binaries in samples/ are gitignored.

$ErrorActionPreference = "Stop"
$samples = Join-Path (Get-Location) "samples"
New-Item -ItemType Directory -Force -Path $samples | Out-Null

function New-ZeroFile($name, $mb) {
    $path = Join-Path $samples $name
    $fs = [System.IO.File]::Create($path)
    $fs.SetLength($mb * 1MB)
    $fs.Close()
    Write-Host "Created $name ($mb MB of zero bytes)"
}

# 1. Empty file (edge case: 0 bytes)
New-Item -ItemType File -Force -Path (Join-Path $samples "empty.exe") | Out-Null
Write-Host "Created empty.exe (0 bytes)"

# 2. Size cap tests (cap is 50 MB): one just under, one just over
New-ZeroFile "big_45mb.exe" 45
New-ZeroFile "big_51mb.exe" 51

# 3. Non-PE file with a .exe name (should be UNSUPPORTED)
Set-Content -Path (Join-Path $samples "fake_test.exe") -Value "not a valid PE binary" -Encoding ascii
Write-Host "Created fake_test.exe (not a PE)"

# 4. EICAR standard antivirus test string (harmless)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path (Join-Path $samples "eicar.com") -Value $eicar -Encoding ascii -NoNewline
Write-Host "Created eicar.com"

# 5. Normal Windows baseline (copy, never the original)
Copy-Item "$env:SystemRoot\System32\hostname.exe" (Join-Path $samples "hostname.exe") -Force
Write-Host "Copied hostname.exe (baseline)"

# 6. UPX-packed copy (needs upx.exe in the project root)
$packed = Join-Path $samples "hostname_upx.exe"
if (Test-Path ".\upx.exe") {
    Remove-Item $packed -Force -ErrorAction SilentlyContinue
    & .\upx.exe --force -o $packed (Join-Path $samples "hostname.exe")
    if (Test-Path $packed) { Write-Host "Created hostname_upx.exe" }
    else { Write-Warning "UPX did not create hostname_upx.exe. Try another program." }
}
else {
    Write-Warning "upx.exe not found in project root. Skipping the packed sample."
}

Write-Host "`nDone. Files in samples/:"
Get-ChildItem $samples | Select-Object Name, Length
