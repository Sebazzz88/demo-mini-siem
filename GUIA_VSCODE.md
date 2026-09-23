# Guía de VS Code para este proyecto

Esta guía usa la carpeta `mini-siem` que acabamos de crear. VS Code no es el
programa que ejecuta Python: es el lugar en el que ves, editas, pruebas y
depuras los archivos del proyecto.

## 1. Abrir el proyecto

1. Abre **Visual Studio Code**.
2. Ve a **File > Open Folder...**.
3. Elige la carpeta `mini-siem`, no la carpeta `src` que está dentro.
4. En el panel izquierdo, pulsa el icono de los dos documentos: es el
   **Explorer**. Ahí verás todos los archivos.

## 2. Extensiones útiles

Abre el icono de extensiones (los cuatro cuadros de la barra izquierda) y busca:

- **Python** de Microsoft. Es la imprescindible: incluye la ejecución, el
  depurador y las pruebas de Python; también instala Pylance normalmente.
- **SQLite** de `alexcvzz`, cuando lleguemos al Módulo 3. Te dejará abrir,
  explorar y consultar el archivo `.db` dentro de VS Code.

No instales extensiones al azar: las dos anteriores son suficientes para este
proyecto al principio.

## 3. Crear el entorno de Python

Abre **Terminal > New Terminal** dentro de VS Code. Ejecuta una sola vez:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Después pulsa `Ctrl+Shift+P`, escribe **Python: Select Interpreter** y elige el
intérprete que diga `.venv`. Así VS Code sabe que debe usar las dependencias del
proyecto y no las de otros programas.

## 4. Configurar el acceso del panel

En el Explorer, selecciona `.env.example`, cópialo y crea un archivo nuevo
llamado exactamente `.env`. Cambia la contraseña y la clave secreta. `.env` no
se sube a Git gracias a `.gitignore`.

```text
MINISIEM_USERNAME=admin
MINISIEM_PASSWORD=tu-clave-personal-aqui
MINISIEM_SECRET_KEY=una-cadena-larga-aleatoria
MINISIEM_PORT=5000
```

 5. Ejecutar la web

Tienes dos formas:

### Desde la terminal integrada

```powershell
.\.venv\Scripts\python.exe run_web.py
```

Abre `http://127.0.0.1:5000` en el navegador. Para detener el servidor, vuelve
a la terminal y pulsa `Ctrl+C`.

### Con el botón de Run and Debug

1. Pulsa el icono de **Run and Debug** (triángulo con un insecto) en la barra
   izquierda.
2. Selecciona `Mini-SIEM: ejecutar panel local`.
3. Pulsa el triángulo verde o `F5`.

El archivo `.vscode/launch.json` ya contiene esta configuración. Si cambias
Python o las variables de `.env`, detén el servidor y vuelve a iniciarlo.

## 6. Usar un breakpoint

Un *breakpoint* pausa el programa antes de una línea para que puedas ver qué
datos tiene.

1. Abre `src/mini_siem/web.py`.
2. Haz clic en el margen izquierdo de una línea dentro de `create_demo`.
   Aparecerá un punto rojo.
3. Inicia el panel con `F5`, entra y pulsa **Generar 31 eventos de demo**.
4. VS Code se pausará. Mira las secciones **Variables** y **Call Stack** de
   Run and Debug.
5. Pulsa `F10` para ejecutar una línea más o `F5` para continuar.

## 7. Ejecutar las pruebas

En la terminal integrada:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Una prueba es un programa pequeño que confirma que otra parte funciona. Antes
de añadir el detector del Módulo 2, ejecutaremos esta orden para asegurarnos de
no romper el recolector ni la web.

## Cómo están organizados los archivos

| Ruta | Para qué sirve |
| --- | --- |
| `run_web.py` | Enciende el servidor web local. |
| `src/mini_siem/web.py` | Rutas Flask: login, demo, recolección y API local. |
| `src/mini_siem/parsers.py` | Entiende líneas SSH, Apache y Nginx. |
| `src/mini_siem/simulator.py` | Crea logs falsos y seguros para la demo. |
| `src/mini_siem/templates/` | HTML de las páginas. |
| `src/mini_siem/static/` | Apariencia CSS y JavaScript del navegador. |
| `tests/` | Pruebas automáticas. |
| `instance/` | Datos temporales locales; en el Módulo 3 tendrá la base SQLite. |

Por ahora concentraremos los cambios de lógica en `src/mini_siem/`. No necesitas
memorizar todo: abre un archivo, lee el comentario inicial y prueba pequeños
cambios de uno en uno.

