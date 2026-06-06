@echo off
REM =====================================================================
REM   IDS - Lanzador de la DEMO para Windows
REM   Crea el entorno la primera vez, genera el escenario y ejecuta el IDS.
REM   La demo (.pcap) NO requiere permisos de administrador ni Npcap.
REM   Uso: doble clic en este archivo (o ejecutar run_demo.bat)
REM =====================================================================
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python no esta instalado o no esta en el PATH.
  echo Descargalo de https://www.python.org/downloads/ y marca "Add Python to PATH".
  pause
  exit /b 1
)

if not exist venv\Scripts\python.exe (
  echo [setup] Primera vez: creando entorno e instalando dependencias...
  python -m venv venv
  venv\Scripts\python.exe -m pip install --upgrade pip
  venv\Scripts\python.exe -m pip install -r requirements.txt
)

if not exist tools\demo.pcap (
  echo [setup] Generando escenario de demostracion...
  venv\Scripts\python.exe tools\make_demo_pcap.py
)

echo [run] Iniciando IDS en modo DEMO...
echo       (para el panel web, ejecuta en otra ventana: run_dashboard.bat)
echo.
venv\Scripts\python.exe -m src.main --pcap tools\demo.pcap
pause
