$WshShell = New-Object -ComObject WScript.Shell

$projectDir = "C:\Users\hamza\Desktop\HFS-Sentry"
$exePath = "$projectDir\dist\HFS-Sentry.exe"
$pythonw = "C:\Python314\pythonw.exe"
$sentryScript = "$projectDir\sentry.py"
$iconPath = "$projectDir\assets\icon.ico"
$desktopDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)

if (Test-Path $exePath) {
    # 1. Shortcut on Desktop pointing to Standalone EXE
    try {
        $sDesktop = $WshShell.CreateShortcut("$desktopDir\HFS-Sentry Suite.lnk")
        $sDesktop.TargetPath = $exePath
        $sDesktop.Arguments = ""
        $sDesktop.WorkingDirectory = "$projectDir\dist"
        $sDesktop.IconLocation = "$iconPath,0"
        $sDesktop.Description = "HFS-Sentry — Cybersecurity Diagnostic Suite (Standalone)"
        $sDesktop.Save()
    } catch {
        Write-Warning "Could not write desktop shortcut: $_"
    }

    # 2. Shortcut in Project Folder
    $sProj = $WshShell.CreateShortcut("$projectDir\HFS-Sentry.lnk")
    $sProj.TargetPath = $exePath
    $sProj.Arguments = ""
    $sProj.WorkingDirectory = "$projectDir\dist"
    $sProj.IconLocation = "$iconPath,0"
    $sProj.Description = "HFS-Sentry — Cybersecurity Diagnostic Suite (Standalone)"
    $sProj.Save()
} else {
    # Fallback to pythonw script launcher
    try {
        $sDesktop = $WshShell.CreateShortcut("$desktopDir\HFS-Sentry Suite.lnk")
        $sDesktop.TargetPath = $pythonw
        $sDesktop.Arguments = "`"$sentryScript`""
        $sDesktop.WorkingDirectory = $projectDir
        $sDesktop.IconLocation = "$iconPath,0"
        $sDesktop.Description = "HFS-Sentry — Cybersecurity Diagnostic Suite"
        $sDesktop.Save()
    } catch {
        Write-Warning "Could not write desktop shortcut: $_"
    }

    $sProj = $WshShell.CreateShortcut("$projectDir\HFS-Sentry.lnk")
    $sProj.TargetPath = $pythonw
    $sProj.Arguments = "`"$sentryScript`""
    $sProj.WorkingDirectory = $projectDir
    $sProj.IconLocation = "$iconPath,0"
    $sProj.Description = "HFS-Sentry — Cybersecurity Diagnostic Suite"
    $sProj.Save()
}

Write-Host "Shortcuts updated successfully!"

