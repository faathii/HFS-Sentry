# Guía de Contribución a HFS-Sentry / Contributing to HFS-Sentry

¡Gracias por tu interés en contribuir a **HFS-Sentry**! Este proyecto es de código abierto (Open Source) bajo licencia MIT y está diseñado para ser accesible, comprensible y extensible para toda la comunidad de ciberseguridad y desarrollo.

---

## 📌 Principios Fundamentales del Proyecto

1. **Cero Dependencias Externas:** El núcleo de HFS-Sentry y todas sus herramientas deben funcionar exclusivamente utilizando la **biblioteca estándar de Python 3** (`socket`, `ssl`, `hashlib`, `concurrent.futures`, `re`, `argparse`, `urllib.request`, etc.). No se permiten dependencias como `requests`, `scapy` o `cryptography` en el runtime base.
2. **Modularidad Total:** Cada herramienta es un módulo independiente que hereda de `BaseTool`. Puede ejecutarse tanto a través de la CLI principal (`python sentry.py <herramienta>`) como de forma aislada (`python -m sentry.tools.<herramienta>`).
3. **Alto Rendimiento y Bajo Overhead:** Diseñado para ejecutarse en entornos mínimos (servidores de producción, contenedores sin internet, consolas de rescate, Raspberry Pi).
4. **Claridad de Código:** Código limpio, tipado estático con `typing`, docstrings explicativos y cumplimiento de PEP 8.

---

## 🛠️ Cómo Añadir una Nueva Herramienta en 3 Pasos

HFS-Sentry utiliza un sistema de **registro dinámico** basado en la clase base `BaseTool`.

### Paso 1: Crea tu archivo en `sentry/tools/`
Crea un nuevo archivo, por ejemplo `sentry/tools/dnsprobe.py`.

```python
from typing import Any, Dict
import argparse
from sentry.core.base import BaseTool
from sentry.core.registry import register_tool

@register_tool
class DnsProbeTool(BaseTool):
    name = "dnsprobe"
    description = "Inspección rápida de registros DNS y servidores de nombres"
    author = "Tu Nombre / GitHub Username"
    version = "1.0.0"
    category = "Network"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("domain", help="Dominio objetivo a resolver")
        parser.add_argument("--record-type", default="A", help="Tipo de registro DNS (A, MX, TXT)")
        parser.add_argument("--json", action="store_true", help="Salida en formato JSON")

    def run(self, args: argparse.Namespace) -> int:
        print(f"Analizando {args.domain}...")
        # Lógica usando la biblioteca estándar (ej. socket.gethostbyname_ex)
        return 0
```

### Paso 2: Importa tu herramienta en `sentry/tools/__init__.py`
Añade una línea para que el registro dinámico la descubra:

```python
from sentry.tools.dnsprobe import DnsProbeTool
```

¡Listo! La herramienta estará disponible inmediatamente en `python sentry.py --list` y con su propia ayuda en `python sentry.py dnsprobe --help`.

### Paso 3: Añade Pruebas Unitarias
Crea su correspondiente prueba en `tests/test_dnsprobe.py` utilizando `unittest` estándar.

---

## 🧪 Ejecución de Pruebas

Para ejecutar la suite completa de pruebas sin instalar nada adicional:

```bash
python -m unittest discover tests
```

---

## 🚀 Flujo de Trabajo para Pull Requests (PR)

1. Haz un **Fork** del repositorio: [https://github.com/faathii/HFS-Sentry](https://github.com/faathii/HFS-Sentry)
2. Crea una rama para tu funcionalidad o corrección:
   ```bash
   git checkout -b feature/nueva-herramienta
   ```
3. Realiza tus cambios y verifica que todas las pruebas pasen.
4. Haz commit siguiendo [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat(tools): add dnsprobe utility for DNS inspection"
   ```
5. Sube tu rama a tu fork:
   ```bash
   git push origin feature/nueva-herramienta
   ```
6. Abre un **Pull Request** hacia la rama `main` en GitHub.
