$WshShell = New-Object -ComObject WScript.Shell

$projectDir = "C:\Users\hamza\Desktop\HFS-Sentry"
$pythonw = "C:\Python314\pythonw.exe"
$sentryScript = "$projectDir\sentry.py"
$iconPath = "$projectDir\assets\icon.ico"

# 1. Shortcut in Project Folder
$s1 = $WshShell.CreateShortcut("$projectDir\HFS-Sentry.lnk")
$s1.TargetPath = $pythonw
$s1.Arguments = "`"$sentryScript`""
$s1.WorkingDirectory = $projectDir
$s1.IconLocation = "$iconPath,0"
$s1.Description = "HFS-Sentry — Cybersecurity Diagnostic Suite"
$s1.Save()

# 2. Shortcut on Desktop
$desktopDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$s2 = $WshShell.CreateShortcut("$desktopDir\HFS-Sentry Suite.lnk")
$s2.TargetPath = $pythonw
$s2.Arguments = "`"$sentryScript`""
$s2.WorkingDirectory = $projectDir
$s2.IconLocation = "$iconPath,0"
$s2.Description = "HFS-Sentry — Cybersecurity Diagnostic Suite"
$s2.Save()

Write-Host "Shortcuts created successfully!"

