# DeskRemote — Análisis Técnico de AnyDesk y Arquitectura en Python

## 1. Cómo funciona AnyDesk (Software de Referencia)

AnyDesk se destaca frente a herramientas clásicas (como VNC o RDP tradicional) por tres pilares de ingeniería:

### 1.1 Códec de Video Propietario: DeskRT
- **Problema tradicional:** Enviar capturas JPEG/PNG completas de la pantalla consume ancho de banda elevado y genera latencia visible.
- **Solución de AnyDesk:** El códec **DeskRT** está optimizado para interfaces gráficas de usuario (ventanas, texto nítido, áreas estáticas). Analiza cada fotograma contra el anterior y transmite **únicamente los bloques o regiones que cambiaron** (*dirty rectangles*), adaptando la compresión dinámicamente según el ancho de banda disponible.
- **Resultado:** Fluidez de hasta 60 FPS con latencias sub-fotograma (<16 ms en LAN) y consumos desde ~100 KB/s.

### 1.2 Arquitectura de Seguridad (E2EE)
- **Autenticación e intercambio asimétrico:** Emplea criptografía asimétrica (**RSA-2048**) para verificar la identidad criptográfica de cada equipo (evitando ataques *Man-in-the-Middle*) y negociar las claves de sesión.
- **Cifrado de transporte autenticado:** Protege toda la sesión (video, teclado, ratón, archivos y portapapeles) mediante **TLS 1.2 / 1.3** con cifrado simétrico **AES-256-GCM (AEAD)** y verificación de huella digital (*fingerprint*).
- **Zero-Knowledge:** Incluso cuando el tráfico atraviesa servidores relay intermedios, los servidores no poseen las claves de sesión y no pueden descifrar ningún byte.

### 1.3 NAT Traversal y Servidores Rendezvous
- **Servidores Rendezvous:** Una red global ligera donde cada equipo mantiene una conexión saliente. Solo actúan como punto de encuentro para resolver IDs de 9 dígitos e intercambiar direcciones IP/puerto.
- **Conexión Directa P2P (Hole Punching):** Siempre que el NAT lo permite, AnyDesk establece una conexión directa UDP/TCP entre ambos equipos.
- **Fallback a Relay:** Ante NAT simétrico o firewalls corporativos estrictos, redirige el flujo cifrado de extremo a extremo a través de un relay sin pérdida de privacidad.

---

## 2. Opciones Técnicas para Desarrollarlo en Python

| Capa | Alternativas en Python | Decisión en DeskRemote | Justificación |
| :--- | :--- | :--- | :--- |
| **Interfaz Gráfica** | `PyQt6`, `Tkinter`, `CustomTkinter`, `Flet` | **`CustomTkinter`** | Requisito del proyecto; aspecto moderno oscuro/claro, ligero y nativo en Python sin frameworks web pesados. |
| **Iconos Vectoriales** | `cairosvg` (requiere DLLs GTK/Cairo), PNG estáticos, dibujo vectorial HiDPI | **Definiciones SVG + Rasterizador Vectorial 4x Supersampled** | Cero dependencias nativas problemáticas en Windows, nítidos en pantallas HiDPI y adaptables automáticamente a tema claro/oscuro. |
| **Captura de Pantalla** | `pyautogui` (lento), `dxcam` (solo Windows/DXGI), `mss` (multiplataforma, C-level) | **`mss` + Motor Delta-Frames** | Ultra-estable (compatible incluso con Python 3.15), rápido y multiplataforma. Combinado con `ImageChops.difference().getbbox()` (ejecutado en C dentro de Pillow), envía solo el rectángulo modificado (inspirado en DeskRT). |
| **Control de Entrada** | `pyautogui`, `keyboard`/`mouse`, `pynput` | **`pynput` + mapeo normalizado `[0..1]`** | Soporta ratón completo (movimiento, clics, arrastre, rueda), teclado completo, modificadores y atajos del sistema, independiente de resolución/DPI. |
| **Cifrado E2EE (v2)** | `Fernet` (clave estática), `ssl` (requiere PKI/certs), **`cryptography` + PAKE** | **SPAKE2 (RFC 9382 P-256) + `scrypt` + X25519 + Ed25519 (DPAPI) + AES-256-GCM** | **SPAKE2** elimina matemáticamente ataques de diccionario offline contra el PIN incluso ante un túnel MitM activo; **X25519** aporta *Perfect Forward Secrecy*; **Ed25519** (cifrada en reposo con Windows DPAPI) + almacén **TOFU** verifica identidades y detecta cambios de clave; **AES-256-GCM** con nonces monotónicos protege el transporte a máxima velocidad. |
| **Servidor Temporal + Acceso WAN (Fuera de LAN)** | VPS propio (requiere servidor permanente), `ngrok` (requiere cuenta/token), `bore.pub`, SSH Tunnel (`pinggy`/`serveo`), `UPnP` | **Servidor Temporal en el Anfitrión + Motor WAN Multi-Estrategia** | El **Anfitrión** levanta su propio servidor TCP efímero local y lo publica automáticamente a Internet sin cuentas obligatorias mediante: 1) **Cliente nativo en Python puro del protocolo Bore (`bore.pub`)**, 2) **Túnel SSH inverso** (`ssh.exe` nativo de Windows → Pinggy/Serveo), 3) **UPnP IGD en Python puro** (SSDP+SOAP), y 4) **LAN directa**. |

---

## 3. Flujo de Conexión: Servidor Temporal en el Anfitrión (Acceso Total al Huésped)

En lugar de depender de un servidor central propio permanente, DeskRemote usa una arquitectura de **Servidor Temporal en el Anfitrión con Conexión Inversa Segura**:

```
┌──────────────────────────────────┐                     ┌──────────────────────────────────┐
│        SISTEMA ANFITRIÓN         │                     │         SISTEMA HUÉSPED          │
│     (Operador / Controlador)     │                     │       (Equipo Controlado)        │
├──────────────────────────────────┤                     ├──────────────────────────────────┤
│ 1. Inicia Servidor Temporal TCP  │                     │                                  │
│ 2. Expone a Internet vía Túnel   │◄── Túnel WAN ──────►│ 3. Ingresa Código + PIN y        │
│    (Bore / SSH / UPnP / LAN)     │    (Sin puertos     │    se conecta saliente al        │
│ 3. Genera Código DR-... + PIN    │     en el huésped)  │    Servidor Temporal             │
│                                  │                     │                                  │
│ ◄════════════ Handshake E2EE (X25519 + Ed25519 + PIN + HMAC Transcript) ════════════════► │
│                                  │                     │                                  │
│ ◄════════════ Canal Cifrado AES-256-GCM (Video Delta, Input, Archivos, Shell) ══════════► │
│                                  │                     │                                  │
│ • Control total ratón/teclado    │                     │ • Captura pantalla (Delta)       │
│ • Gestor de archivos bidirec.    │                     │ • Inyección de entrada (pynput)  │
│ • Terminal remota (PowerShell)   │                     │ • Ejecución comandos / procesos  │
│ • Portapapeles y telemetría      │                     │ • Revocación instantánea         │
└──────────────────────────────────┘                     └──────────────────────────────────┘
```

### Ventajas Clave de esta Arquitectura
1. **El Huésped funciona desde cualquier red** (Wi-Fi doméstico, datos móviles 4G/5G, NAT estricto/CGNAT, oficina) porque únicamente realiza una conexión TCP saliente.
2. **El Anfitrión crea un servidor temporal efímero**: al cerrar la sesión, el servidor y el túnel se destruyen completamente; no queda ningún puerto ni demonio expuesto.
3. **Privacidad total (Zero-Knowledge)**: el túnel público (Bore/Pinggy/Serveo) únicamente transporta paquetes TCP opacos cifrados con **AES-256-GCM** cuyas claves fueron derivadas exclusivamente entre Anfitrión y Huésped usando **X25519 + PIN secreto**. Un intermediario no puede leer ni inyectar tráfico ni suplantar a ninguno de los dos extremos.
