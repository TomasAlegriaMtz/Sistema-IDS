@echo off
REM =====================================================================
REM   IDS - Panel web (dashboard) para Windows
REM   Uso: doble clic -> luego abre http://127.0.0.1:5000 en el navegador
REM =====================================================================
cd /d "%~dp0"

if not exist venv\Scripts\python.exe (
  echo Primero ejecuta run_demo.bat (instala el entorno).
  pause
  exit /b 1
)

echo Dashboard del IDS en: http://127.0.0.1:5000   (cierra esta ventana para detener)
venv\Scripts\python.exe -m src.web.app
pause
