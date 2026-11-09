# Suite de Herramientas de Ciberseguridad & Diagnóstico de Infraestructuras
> **Autor:** Hamza El Fathi Sofyani  
> **Acreditación:** Certificado en Ciberseguridad por Cisco Networking Academy | Grado en Ingeniería Informática (UNED)  
> **Objetivo:** Colección de utilidades técnicas de alta densidad, bajo overhead y cero dependencias externas (Python 3 estándar) orientadas a la auditoría perimetral, análisis forense de logs y endurecimiento (*hardening*) de sistemas.

---

## Índice de Utilidades Técnicas

1. [NetSentry — Escáner Concurrente de Puertos & Auditor de Cabeceras HTTP](#1-netsentry--escáner-concurrente-de-puertos--auditor-de-cabeceras-http)
2. [LogSentinel — Analizador Forense de Registros & Detección de Intrusiones](#2-logsentinel--analizador-forense-de-registros--detección-de-intrusiones)
3. [CertSentry — Inspector de Caducidad SSL/TLS & Cifrados Criptográficos](#3-certsentry--inspector-de-caducidad-ssltls--cifrados-criptográficos)
4. [SubnetSweep — Descubridor de Activos de Red Local & Mapeo OUI MAC](#4-subnetsweep--descubridor-de-activos-de-red-local--mapeo-oui-mac)
5. [IntegrityGuard — Monitor de Integridad de Archivos Críticos (FIM) con SHA-256](#5-integrityguard--monitor-de-integridad-de-archivos-críticos-fim-con-sha-256)

---

## 1. NetSentry — Escáner Concurrente de Puertos & Auditor de Cabeceras HTTP

* **Tiempo estimado de desarrollo:** 1 hora.
* **Propósito:** Descubrimiento no invasivo de servicios expuestos y verificación estática de las 6 cabeceras de seguridad recomendadas por OWASP.
* **Dominio Técnico:** Programación concurrente (`ThreadPoolExecutor`), sockets TCP/IP y análisis de protocolos web sin librerías de terceros (`urllib`/`ssl`).

### Arquitectura Técnica
```
[ Host Objetivo ] ──> Sockets TCP Concurrencia (Pool 20 Hilos) ──> [ Mapeo Puertos Abiertos ]
                             │
                             └── Si Puerto 80/443 Abierto ────> [ Handshake SSL & HTTP GET ]
                                                                        │
                                                                 [ Auditor Cabeceras ]
                                                                 ├── HSTS (Downgrade MitM)
                                                                 ├── CSP (Mitigación XSS)
                                                                 ├── X-Frame-Options (Clickjack)
                                                                 └── Permissions-Policy
```

### Características Clave
* **Sondeo en Paralelo:** Escanea 15 puertos estándar (21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8080) en menos de 0.8 segundos.
* **Banner Grabbing Ligero:** Captura los primeros 128 bytes del servicio para identificar software de servidor (OpenSSH, Nginx, Apache).
* **Calificación Automatizada:** Evalúa el nivel de endurecimiento (Grado A, B o F) según el cumplimiento de directrices CIS/OWASP.
* **Alertas Críticas:** Identifica puertos heredados de texto plano vulnerables a interceptación (ej. Telnet puerto 23 o FTP puerto 21).

---

## 2. LogSentinel — Analizador Forense de Registros & Detección de Intrusiones

* **Tiempo estimado de desarrollo:** 1 hora y 15 minutos.
* **Propósito:** Ingesta y análisis forense de archivos de registro (`auth.log`, `secure`, o `access.log` de Nginx) para correlacionar vectores de ataque y generar contramedidas activas.
* **Dominio Técnico:** Expresiones regulares vectorizadas, agregación estadística y automatización de reglas de cortafuegos (`iptables`/`ufw`).

### Casos de Uso Detectados
1. **Fuerza Bruta SSH:** Identifica IPs con más de $N$ autenticaciones fallidas consecutivas (`Failed password for invalid user ...`).
2. **Directory Traversal:** Detecta peticiones HTTP anómalas dirigidas a rutas del sistema (`/etc/passwd`, `/win.ini`, `../../`).
3. **Escaneos de Herramientas Automatizadas:** Filtra peticiones con User-Agents característicos de escáneres de vulnerabilidades (Nikto, SQLmap, Acunetix).

### Salida Generada
* Tabla en consola con IPs atacantes, país o subred y recuento de intentos.
* Archivo ejecutable generado al vuelo: `block_threats.sh` con comandos listos:
  ```bash
  sudo ufw deny from 198.51.100.42 to any comment 'LogSentinel: Brute-Force SSH'
  ```

---

## 3. CertSentry — Inspector de Caducidad SSL/TLS & Cifrados Criptográficos

* **Tiempo estimado de desarrollo:** 45 minutos.
* **Propósito:** Auditoría preventiva del estado de los certificados X.509 de una infraestructura corporativa y verificación de protocolos de cifrado seguros.
* **Dominio Técnico:** Criptografía de clave pública, negociación TLS 1.2/1.3, manejo del módulo `ssl` y parseo de certificados X.509.

### Funcionalidades
* **Cálculo de Vida Útil Restante:** Alerta en semáforo de colores si el certificado expira en menos de 30, 15 o 7 días.
* **Inspección de la Cadena de Confianza:** Verifica emisor (CA), Subject Alternative Names (SANs) y número de serie.
* **Detección de Cifrados Obsoletos:** Verifica si el servidor todavía permite negociaciones inseguras en TLS 1.0 o TLS 1.1 o algoritmos con vulnerabilidades conocidas (RC4, 3DES, CBC).

---

## 4. SubnetSweep — Descubridor de Activos de Red Local & Mapeo OUI MAC

* **Tiempo estimado de desarrollo:** 1 hora.
* **Propósito:** Inventariado rápido de dispositivos conectados a la subred local (impresoras, servidores, placas Raspberry Pi, cámaras IP) mediante tramas controladas.
* **Dominio Técnico:** Protocolos ARP/ICMP, cálculo de máscaras CIDR (/24) y resolución de identificadores OUI (*Organizationally Unique Identifier*).

### Funcionalidades
* **Barrido ICMP Concurrente:** Envía ecos ICMP (o prueba de apertura de sockets en hosts Windows/Linux) a 254 direcciones en paralelo.
* **Identificación del Fabricante:** Cruza los primeros 3 octetos de la MAC detectada contra la base de datos de fabricantes de la IEEE (identificando placas Raspberry Pi Foundation, tarjetas Espressif/Arduino, Cisco Systems o routers domésticos).
* **Exportación para Auditoría:** Salida estructurada en JSON o tabla formateada para memorias de laboratorio.

---

## 5. IntegrityGuard — Monitor de Integridad de Archivos Críticos (FIM) con SHA-256

* **Tiempo estimado de desarrollo:** 1 hora.
* **Propósito:** Sistema ligero de detección de intrusiones a nivel de host (HIDS) que vigila la inmutabilidad de archivos sensibles del sistema operativo.
* **Dominio Técnico:** Algoritmos de dispersión criptográfica (`hashlib.sha256`), almacenamiento local estructurado y detección de discrepancias por alteración no autorizada.

### Cómo Opera
1. **Línea Base (*Baseline*):** Genera una firma criptográfica SHA-256 de archivos críticos:
   * `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` (en Linux).
   * `C:\Windows\System32\drivers\etc\hosts` (en Windows).
   * Scripts daemon de automatización (ej. los daemons de `iQsense`).
2. **Modo Monitoreo / Escaneo:** Compara el estado actual frente a la línea base almacenada.
3. **Alertas en Milisegundos:**
   * Archivo modificado (hash alterado).
   * Metadatos o permisos cambiados.
   * Nuevos archivos sospechosos inyectados en el directorio vigilado.

---

## Resumen de Valor para Entrevistas y Demostraciones

| Utilidad | Área Principal | Valor Demostrable en Reunión |
| :--- | :--- | :--- |
| **NetSentry** | Redes & Web | Concurrencia real en Python + directrices CIS de cabeceras web. |
| **LogSentinel** | Hardening & SOC | Capacidad para analizar incidentes y aplicar contramedidas en cortafuegos. |
| **CertSentry** | Criptografía | Dominio de infraestructura PKI, TLS y ciclo de vida de certificados. |
| **SubnetSweep** | Infraestructura | Dominio del direccionamiento IP, ARP y auditoría de hardware conectado. |
| **IntegrityGuard** | HIDS / Forense | Principio de inmutabilidad y verificación criptográfica de integridad. |

