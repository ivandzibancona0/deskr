# DeskRemote (v1.1.0) — Escritorio Remoto Cifrado E2EE en Python

Aplicación de escritorio remoto inspirada en **AnyDesk** y **TeamViewer**, desarrollada en **Python** con **CustomTkinter**, **iconos vectoriales minimalistas**, **cifrado de extremo a extremo v2 (SPAKE2 + X25519 + Ed25519 + AES-256-GCM)**, **servidor temporal integrado en el anfitrión**, **conectividad global fuera de la red local (WAN)** y **empaquetado en un único ejecutable portable de Windows (`DeskRemote.exe`)**.

---

## Características Principales

### Conectividad Global y Servidor Temporal
- **Servidor Temporal en el Anfitrión:** El equipo anfitrión crea un servidor TCP efímero bajo demanda (modo **sesión única** por defecto) y lo destruye automáticamente al detenerlo o cerrar la aplicación.
- **Acceso desde Cualquier Red (WAN / CGNAT / LAN):** Motor multi-estrategia automático:
  1. **Túnel TCP Global Bore (`bore.pub` o servidor propio):** Cliente nativo en Python puro (sin binarios externos ni cuentas).
  2. **Túnel SSH Inverso (`Pinggy` / `Serveo`):** Vía OpenSSH nativo con archivo `known_hosts` TOFU dedicado (`~/.deskremote/tunnel_known_hosts`, `StrictHostKeyChecking=accept-new`).
  3. **UPnP IGD en Python puro:** Mapeo automático en routers compatibles con *lease* reducido (`1800s`) y limpieza garantizada mediante `atexit`.
  4. **Red Local Directa (LAN):** Conexión directa de latencia mínima en la misma red o VPN.
- **Conexión Directa (Modo Clásico Opcional):** Permite invertir el rol para que el Huésped escuche temporalmente y el Anfitrión se conecte hacia él.

### Seguridad y Cifrado de Extremo a Extremo (E2EE v2 — Zero-Knowledge)
- **PAKE SPAKE2 (RFC 9382 sobre NIST P-256) + `scrypt` (32 MiB):** Intercambio autenticado por contraseña con validación estricta de puntos sobre curva. Elimina ataques de diccionario offline sobre el PIN incluso si un túnel intermedio actúa como MitM activo.
- **PIN Criptográfico de 8 caracteres (`XXXX-XXXX`):** ~39.6 bits de entropía con **rotación automática tras 3 intentos fallidos** y botón de rotación manual.
- **X25519 (ECDH Efímero):** *Perfect Forward Secrecy (PFS)* por sesión.
- **Identidad Ed25519 protegida con DPAPI:** Clave persistente protegida en reposo con **Windows DPAPI** (`CryptProtectData`) en `~/.deskremote/identity_ed25519.key` (y permisos `0600` en POSIX).
- **Almacén de Confianza TOFU (`known_peers.json`) + Diálogo de Aprobación:** Antes de iniciar cada sesión, un modal muestra el nombre del equipo remoto, su huella Ed25519, la huella de sesión y el estado TOFU (*Equipo Conocido*, *Nuevo Equipo* o *¡Alerta: Clave Cambiada!*).
- **Protección Anti-DoS y Roles Estrictos:** Handshakes concurrentes acotados por semáforo (`max=4`, timeout `8s`) y validación obligatoria de roles complementarios (`Anfitrión ↔ Huésped`).
- **Transporte AES-256-GCM (AEAD):** Claves direccionales independientes, nonces monotónicos de 96 bits (anti-*replay*) y AAD por trama.
- **Auditoría Persistente Rotativa:** Eventos de seguridad, sesiones, permisos, terminal y archivos registrados en `~/.deskremote/logs/audit.log` (5 MB × 3 archivos, sin afectar FPS ni registrar fotogramas).

### Acceso Total del Anfitrión al Huésped (**DeskRemote Studio**)
- **Escritorio Remoto Delta (estilo DeskRT):** Captura `mss` + detección de regiones modificadas (*dirty rectangles*) en C (Pillow), selección multi-monitor, 4 presets de calidad (`Baja`, `Balanceada`, `Alta`, `Ultra`) y recuperación automática ante pantallas protegidas/UAC de Windows.
- **Control Completo de Ratón y Teclado:** Coordenadas normalizadas HiDPI, clics, arrastre, rueda, teclado completo y atajos del sistema (`Win`, `Alt+Tab`, `Ctrl+Shift+Esc`, `Win+R`, `Win+D`, `Win+E`, `Alt+F4`, `Win+L`).
- **Gestor de Archivos Bidireccional Endurecido:** Exploración de unidades/carpetas, subida y descarga cifrada en bloques con escritura atómica `.part`, verificación **SHA-256**, confirmación antes de sobrescribir archivos existentes, validación de espacio libre en disco (límite 2 GiB) y revocación inmediata por chunk si el huésped desactiva el permiso en vivo.
- **Terminal Remota Cifrada:** Consola PowerShell (Windows) / Bash (POSIX) con directorio persistente (`cd`) e historial con `↑ / ↓`.
- **Sistema, Procesos y Energía:** Telemetría CPU/RAM/Disco en vivo, finalización de procesos por PID, bloqueo, reinicio, apagado y captura PNG sin pérdida.
- **Portapapeles y Chat Cifrado:** Sincronización bidireccional en 1 clic y chat E2EE integrado.

### Diseño Minimalista y Documentación
- **Interfaz CustomTkinter** con tema **Oscuro / Claro** conmutable, icono propio **`DeskR.ico`** en barra de título y barra de tareas, y **31 iconos vectoriales minimalistas** renderizados con supersampling 4x HiDPI.
- **Manual Profesional de Usuario Interactivo:** [manual_usuario.html](manual_usuario.html) autocontenido con tema claro/oscuro sincronizado, buscador (`Ctrl+K`), diagramas SVG, exportación a PDF y favicon `DeskR.ico`.

---

## Ejecución Rápida

### Opción A — Ejecutable Portable de Windows (sin instalar Python)
Copia únicamente **`DeskRemote.exe`** (ubicado en la raíz del proyecto) a cualquier equipo con **Windows 10/11 (64 bits)** y ábrelo con doble clic.
- No requiere Python ni carpetas o `.dll` adicionales.
- Se ejecuta con privilegios de **usuario estándar** (si necesitas interactuar con cuadros UAC de Windows, haz clic derecho → *Ejecutar como administrador*).
- Los datos persistentes del equipo (`identity_ed25519.key`, `known_peers.json`, `tunnel_known_hosts` y `logs/audit.log`) se almacenan en `%USERPROFILE%\.deskremote\`, manteniendo limpia la carpeta del ejecutable.

### Opción B — Desde Código Fuente (Python 3.10–3.15)
```powershell
# 1. Crear y activar entorno virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Ejecutar la aplicación
python main.py
```

---

## Cómo Usarla (Paso a Paso)

### 1. En el equipo Anfitrión (quien controla)
1. Abre **DeskRemote** en la pestaña **Anfitrión (Controlar)**.
2. Deja el alcance de red en **Automático Global (Recomendado)** (o elige `Bore`, `SSH Pinggy`, `SSH Serveo`, `UPnP` o `LAN`).
3. Pulsa **Iniciar Servidor Temporal**.
4. Copia el **Código de Sesión** (`DR-...`) y el **PIN Criptográfico** de 8 caracteres (`XXXX-XXXX`) y compártelos con el equipo huésped.

### 2. En el equipo Huésped (equipo remoto en cualquier parte del mundo)
1. Abre **DeskRemote** en la pestaña **Huésped (Dar Acceso)**.
2. Pega el **Código de Sesión** y el **PIN**.
3. Pulsa **Conectar y Compartir Acceso Total** y confirma la identidad TOFU en el diálogo de aprobación.
4. En el Anfitrión, acepta la conexión en el diálogo modal para abrir **DeskRemote Studio** con control total cifrado E2EE.

---

## Compilar el Ejecutable Único (`DeskRemote.exe`)

Tras cualquier modificación en el código fuente, regenera `DeskRemote.exe` en la carpeta raíz ejecutando:

```powershell
.\.venv\Scripts\python.exe build_exe.py
```

*(También puedes hacer doble clic en `build_exe.bat`).*

El script [build_exe.py](build_exe.py):
1. Instala/verifica `pyinstaller` en el entorno.
2. Empaqueta Python, Tcl/Tk, todas las librerías (`customtkinter`, `cryptography` + `abi3t-compat/python3t.dll`, `pynput`, `mss`, `pillow`, `psutil`, `pyperclip`, `darkdetect`), metadatos de versión de Windows y el icono `DeskR.ico` en modo `--onefile --windowed`.
3. Coloca **`DeskRemote.exe`** en la carpeta raíz y elimina automáticamente `build/`, `dist/` y `.spec`.
4. Ejecuta una **verificación aislada automática** (`DeskRemote.exe --smoke-test`) en una carpeta temporal limpia sin `PYTHONPATH` ni `.venv` para confirmar que todas las librerías cargan sin archivos externos.

---

## Estructura del Proyecto

```text
DeskRemote - Piloto/
├── DeskRemote.exe          # Ejecutable único portable de Windows (64 bits)
├── DeskR.ico               # Icono de la aplicación, ejecutable y favicon del manual
├── main.py                 # Punto de entrada (modo fuente, frozen y --smoke-test)
├── build_exe.py            # Script automatizado de compilación --onefile + verificación
├── build_exe.bat           # Lanzador rápido en Windows para build_exe.py
├── manual_usuario.html     # Manual profesional de usuario interactivo (HTML/CSS/JS)
├── ARCHITECTURE.md         # Análisis técnico de AnyDesk y arquitectura en Python
├── requirements.txt        # Dependencias Python
├── deskremote/
│   ├── config.py           # Constantes, límites de seguridad, paleta y ruta de icono
│   ├── crypto/
│   │   ├── spake2.py       # RFC 9382 SPAKE2 sobre NIST P-256 + scrypt
│   │   ├── e2ee.py         # Handshake E2EE v2 (X25519 + Ed25519 DPAPI + AES-256-GCM)
│   │   └── trust_store.py  # Almacén persistente de confianza TOFU (known_peers.json)
│   ├── security/
│   │   └── audit.py        # Logger persistente rotativo de auditoría de seguridad
│   ├── network/
│   │   ├── protocol.py     # Protocolo binario/JSON multiplexado cifrado
│   │   ├── session_code.py # Códigos compactos DR-... y PINs de 8 caracteres
│   │   ├── tunnel.py       # Motor WAN: Bore Python puro, SSH TOFU, UPnP y LAN
│   │   └── server.py       # Servidor temporal anti-DoS, rate-limiting y sesión única
│   ├── remote/
│   │   ├── screen.py       # Captura mss + motor Delta-Frame + fallback pantalla protegida
│   │   ├── input_ctrl.py   # Inyección normalizada de ratón, teclado y atajos
│   │   ├── file_ops.py     # Operaciones del sistema de archivos del huésped
│   │   ├── shell_ops.py    # Terminal remota PowerShell/Bash, procesos y energía
│   │   └── guest_agent.py  # Agente huésped endurecido (permisos por chunk, .part, SHA-256)
│   └── ui/
│       ├── icons.py        # 31 iconos vectoriales minimalistas (4x supersampled + SVG)
│       ├── app.py          # Interfaz principal CustomTkinter + diálogo TOFU
│       └── remote_window.py# Consola DeskRemote Studio (pantalla, archivos, shell, sistema, chat)
└── tests/
    └── test_core.py        # Suite de 18 pruebas de seguridad, integración y UI
```

---

## Pruebas Automatizadas

Ejecuta las **18 pruebas** de criptografía (SPAKE2, E2EE v2, DPAPI, rechazo de roles), TOFU, auditoría, anti-DoS, rotación de PIN, transferencias de archivos endurecidas e interfaz:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

---

## Documentación Adicional
- **Manual de Usuario Interactivo:** abre [manual_usuario.html](manual_usuario.html) en tu navegador.
- **Análisis de Referencia (AnyDesk) y Arquitectura:** consulta [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Licencia
Este proyecto es software de código abierto distribuido bajo la **Licencia MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.
