@echo off
cd /d "%~dp0"

echo [1/3] Preparando entorno de compilacion...
python -m venv build-venv
build-venv\Scripts\python.exe -m pip install --upgrade pip
build-venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller

echo [2/3] Empaquetando el .exe (esto tarda unos minutos)...
build-venv\Scripts\pyinstaller --onefile --name ids --noconfirm ^
  --collect-all scapy --collect-all ipwhois launcher.py

echo [3/3] Copiando config junto al .exe...
xcopy /E /I /Y config dist\config >nul
copy /Y LEEME_EXE.txt dist\ >nul

echo.
echo ============================================================
echo   LISTO. Distribuye la carpeta  dist\  completa:
echo     dist\ids.exe  +  dist\config\
echo   En el equipo destino: instalar Npcap y doble clic en ids.exe.
echo ============================================================
pause
