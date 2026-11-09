@echo off
setlocal enabledelayedexpansion
title Instalador de HFS-Sentry Suite
color 0B

echo ======================================================================
echo           HFS-SENTRY SUITE — INSTALADOR PARA WINDOWS
echo           Suite Modular de Ciberseguridad & Diagnostico
echo           Autor: Hamza El Fathi Sofyani
echo ======================================================================
echo.

cd /d "%~dp0"

echo [+] [1/4] Verificando instalacion de Python 3...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo [!] ERROR: Python 3 no se encuentra en el PATH del sistema.
    echo     Descarguelo e instale desde https://www.python.org/
    pause
    exit /b 1
)
python --version
echo [✔] Python detectado correctamente.

echo.
echo [+] [2/4] Generando icono multi-resolucion (.ico)...
python -c "
from PIL import Image
import os
if not os.path.isfile('assets/icon.ico'):
    img = Image.open('assets/logos/hfs_sentry.png').convert('RGBA')
    w, h = img.size
    m = max(w, h)
    sq = Image.new('RGBA', (m, m), (0, 0, 0, 0))
    sq.paste(img, ((m - w) // 2, (m - h) // 2))
    sq.save('assets/icon.ico', format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
" >nul 2>&1
echo [✔] Icono preparado.

echo.
echo [+] [3/4] Instalando comandos de consola (hfs-sentry)...
pip install -e . >nul 2>&1
echo [✔] Comando registrado: ahora puedes escribir 'hfs-sentry' o 'hfs-sentry-gui'.

echo.
echo [+] [4/4] Creando accesos directos en Menu Inicio y Escritorio...
powershell -ExecutionPolicy Bypass -Command "
$WshShell = New-Object -ComObject WScript.Shell
$projDir = (Get-Location).Path
$pythonw = (Get-Command pythonw.exe).Source
$icoPath = Join-Path $projDir 'assets\icon.ico'
$sentryPy = Join-Path $projDir 'sentry.py'

# 1. Desktop
$deskDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$sDesk = $WshShell.CreateShortcut((Join-Path $deskDir 'HFS-Sentry Suite.lnk'))
$sDesk.TargetPath = $pythonw
$sDesk.Arguments = '\"' + $sentryPy + '\"'
$sDesk.WorkingDirectory = $projDir
$sDesk.IconLocation = $icoPath + ',0'
$sDesk.Description = 'HFS-Sentry Suite — Cybersecurity Desktop Hub'
$sDesk.Save()

# 2. Start Menu
$startMenuDir = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Programs)) 'HFS-Sentry Suite'
if (!(Test-Path $startMenuDir)) { New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null }
$sStart = $WshShell.CreateShortcut((Join-Path $startMenuDir 'HFS-Sentry.lnk'))
$sStart.TargetPath = $pythonw
$sStart.Arguments = '\"' + $sentryPy + '\"'
$sStart.WorkingDirectory = $projDir
$sStart.IconLocation = $icoPath + ',0'
$sStart.Description = 'HFS-Sentry Suite — Cybersecurity Desktop Hub'
$sStart.Save()
" >nul 2>&1

echo [✔] Accesos directos creados exitosamente:
echo     - En tu Escritorio: "HFS-Sentry Suite.lnk"
echo     - En tu Menu Inicio: "Inicio > HFS-Sentry Suite > HFS-Sentry"

echo.
echo ======================================================================
echo  [✔] INSTALACION COMPLETADA EXITOSAMENTE.
echo  Puedes hacer doble clic en el acceso directo de tu Escritorio
echo  o ejecutar 'hfs-sentry-gui' desde cualquier terminal.
echo ======================================================================
echo.
pause

