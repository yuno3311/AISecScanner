# Run this script in PowerShell as Administrator to automate setup
Write-Host "[+] Automated Security Scanner Environment Setup" -ForegroundColor Green

# 1. Disable Windows App Execution Aliases (fixes 'Python' alias bug)
Write-Host "[+] Disabling Windows Store Python Aliases..." -ForegroundColor Yellow
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\python.exe" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\python3.exe" -ErrorAction SilentlyContinue

# 2. Extract JDK 21 if installer or zip exists in root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$JdkPath = Join-Path $ScriptDir "jdk-21_windows-x64_bin"

if (Test-Path $JdkPath) {
    Write-Host "[+] JDK 21 folder found at: $JdkPath" -ForegroundColor Green
    [System.Environment]::SetEnvironmentVariable("JAVA_HOME", $JdkPath, [System.EnvironmentVariableTarget]::User)
    
    $UserPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::User)
    $BinPath = Join-Path $JdkPath "bin"
    if ($UserPath -notlike "*$BinPath*") {
        [System.Environment]::SetEnvironmentVariable("PATH", "$UserPath;$BinPath", [System.EnvironmentVariableTarget]::User)
    }
}

Write-Host "[✔] Environment Setup Complete. Please restart Qt Creator." -ForegroundColor Green