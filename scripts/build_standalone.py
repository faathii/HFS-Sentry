#!/usr/bin/env python3
"""Build helper script to package HFS-Sentry into a standalone single-file Windows executable (.exe).

Requires pyinstaller: pip install pyinstaller
Usage: python scripts/build_standalone.py
"""

import os
import subprocess
import sys


def build_executable():
    print("=" * 60)
    print(" HFS-Sentry Standalone Executable Builder (.exe)")
    print("=" * 60)

    try:
        import PyInstaller
        print(f"[✔] PyInstaller detected (v{PyInstaller.__version__})")
    except ImportError:
        print("[!] PyInstaller no está instalado en este entorno.")
        print("    Para generar el .exe independiente, ejecute:")
        print("    pip install pyinstaller")
        print("    Y vuelva a ejecutar este script.")
        return 1

    icon_path = os.path.join("assets", "icon.ico")
    if not os.path.isfile(icon_path):
        print(f"[!] No se encontró el icono en '{icon_path}'.")
        return 1

    # Separator for PyInstaller --add-data (semicolon on Windows, colon on Unix)
    sep = ";" if sys.platform == "win32" else ":"
    data_arg = f"assets{sep}assets"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=HFS-Sentry",
        "--onefile",
        "--noconsole",
        f"--icon={icon_path}",
        f"--add-data={data_arg}",
        "--clean",
        "sentry.py",
    ]

    print("\n[+] Ejecutando PyInstaller para compilar HFS-Sentry.exe...")
    print(f"Comando: {' '.join(cmd)}\n")

    res = subprocess.run(cmd)
    if res.returncode == 0:
        dist_exe = os.path.join("dist", "HFS-Sentry.exe" if sys.platform == "win32" else "HFS-Sentry")
        print("\n" + "=" * 60)
        print(f"[✔] ¡Compilación completada exitosamente!")
        print(f"    Ejecutable generado en: {os.path.abspath(dist_exe)}")
        print("=" * 60)
        return 0
    else:
        print(f"\n[!] La compilación falló con código {res.returncode}")
        return res.returncode


if __name__ == "__main__":
    sys.exit(build_executable())

