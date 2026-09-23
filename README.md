# Mini-SIEM casero

Aplicación web local para tu laboratorio. Recoge logs, guarda histórico en
SQLite, evalúa reglas de detección y muestra las alertas en un dashboard.
Funciona sin servicios de pago y no realiza escaneos ni conexiones hacia
sistemas de terceros.

Si estás aprendiendo a usar Visual Studio Code, empieza por
[`GUIA_VSCODE.md`](GUIA_VSCODE.md).

## Qué incluye

- Recolector de `auth.log` (SSH), access logs Apache/Nginx y registros UFW.
- Simulador local con 31 eventos de prueba, sin tráfico de red.
- Reglas de fuerza bruta SSH, escaneo de puertos, pico de 404 e indicios de
  inyección SQL en URLs.
- Base SQLite en `instance/mini_siem.db`, con tablas `events` y `alerts`.
- Panel Flask con login, gráficas locales Chart.js, alertas recientes y refresco
  automático cada diez segundos.
- Avisos opcionales por Telegram para alertas altas.
- Guía de práctica en VMs aisladas: [`LAB_VM_GUIDE.md`](LAB_VM_GUIDE.md).

## Ejecutar el panel

En Ubuntu/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 run_web.py
```

En Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python run_web.py
```

Antes de iniciar, abre `.env` y cambia al menos `MINISIEM_PASSWORD` y
`MINISIEM_SECRET_KEY`. Después abre `http://127.0.0.1:5000`. El panel se enlaza
solo a tu propio equipo, no a la red.

## Usar la demo

Inicia sesión y pulsa **Generar demo y alertas**. Generará 31 eventos y cuatro
alertas de muestra:

| Regla | Severidad |
| --- | --- |
| Fuerza bruta SSH | Alta |
| Escaneo de puertos | Alta |
| Pico de errores 404 | Media |
| Posible inyección SQL | Alta |

Puedes ejecutar las pruebas sin abrir el navegador:

```bash
python -m unittest discover -s tests -v
```

## Importar logs de una VM

El panel lee únicamente las carpetas incluidas en
`MINISIEM_LOG_DIRECTORIES`. En Linux el valor por defecto es `/var/log`. En
Windows, define la carpeta compartida de la VM, por ejemplo:

```text
MINISIEM_LOG_DIRECTORIES=C:\MiniSIEM\vm-logs
```

Usa los tres campos de **Importar logs** para `auth.log`, `access.log` y
`ufw.log`. Vuelve a importar cuando quieras: la base evita duplicar la misma
entrada y conserva el histórico.

`target_port` no suele existir en access logs web. La regla de escaneo de
puertos usa UFW, que registra origen (`SRC=`) y puerto destino (`DPT=`).

## Telegram

Es opcional. Las instrucciones y las variables necesarias están en
[`NOTIFICACIONES_TELEGRAM.md`](NOTIFICACIONES_TELEGRAM.md). Sin token y chat ID
configurados, el programa no abre ninguna conexión a Telegram.

