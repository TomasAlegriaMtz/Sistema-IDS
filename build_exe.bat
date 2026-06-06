@echo off
REM =====================================================================
REM   Construye el ejecutable ids.exe (Windows) con PyInstaller.
REM   Requiere Python instalado. Genera la carpeta dist\ lista para
REM   distribuir (ids.exe + config + tools\demo.pcap).
REM =====================================================================
cd /d "%~dp0"

echo [1/4] Preparando entorno de compilacion...
python -m venv build-venv
build-venv\Scripts\python.exe -m pip install --upgrade pip
build-venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller

echo [2/4] Generando el escenario demo.pcap...
build-venv\Scripts\python.exe tools\make_demo_pcap.py

echo [3/4] Empaquetando el .exe (esto tarda unos minutos)...
build-venv\Scripts\pyinstaller --onefile --name ids --noconfirm ^
  --collect-all scapy --collect-all ipwhois launcher.py

echo [4/4] Copiando config y demo junto al .exe...
xcopy /E /I /Y config dist\config >nul
if not exist dist\tools mkdir dist\tools
copy /Y tools\demo.pcap dist\tools\ >nul
copy /Y LEEME_EXE.txt dist\ >nul

echo.
echo ============================================================
echo   LISTO. Distribuye la carpeta  dist\  completa:
echo     dist\ids.exe  +  dist\config\  +  dist\tools\demo.pcap
echo   El profe solo hace doble clic en ids.exe.
echo ============================================================
pause
