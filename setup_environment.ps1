# Run this script in PowerShell as Administrator to automate setup
Write-Host "[+] Automated Security Scanner Environment Setup" -ForegroundColor Green

# 1. Disable Windows App Execution Aliases (fixes 'Python' alias bug)
Write-Host "[+] Disabling Windows Store Python Aliases..." -ForegroundColor Yellow
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\python.exe" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\python3.exe" -ErrorAction SilentlyContinue

# 2. Verify or Automatically Download JDK 21
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$JdkPath = Join-Path $ScriptDir "jdk-21_windows-x64_bin"

if (-not (Test-Path $JdkPath)) {
    Write-Host "[!] JDK 21 folder not found. Downloading dynamically to keep repository size light..." -ForegroundColor Cyan
    $JdkZip = Join-Path $ScriptDir "jdk21.zip"
    $JdkUrl = "https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.exe"
    
    # Download the archive
    Invoke-WebRequest -Uri $JdkUrl -OutFile $JdkZip
    
    # Extract to a temporary location to handle nested folder structures
    $ExtractTemp = Join-Path $ScriptDir "jdk_temp"
    Expand-Archive -Path $JdkZip -DestinationPath $ExtractTemp -Force
    
    # Move the nested inner folder to match your expected 'jdk-21_windows-x64_bin' path
    $InnerFolder = Get-ChildItem -Path $ExtractTemp -Directory | Select-Object -First 1
    Move-Item -Path $InnerFolder.FullName -Destination $JdkPath -Force
    
    # Clean up temporary zip and extraction folder
    Remove-Item $JdkZip -Force
    Remove-Item $ExtractTemp -Recurse -Force
    Write-Host "[+] JDK 21 downloaded and extracted successfully." -ForegroundColor Green
}

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
