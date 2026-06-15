@echo off
REM =============================================
REM Build WebGuardian Desktop for Windows
REM =============================================
echo Building WebGuardian Desktop for Windows...

REM Check Python
python --version >NUL 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found. Please install Python 3.10+.
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: pip install failed.
    exit /b 1
)

REM Install PyInstaller
pip install pyinstaller
if %errorlevel% neq 0 (
    echo Error: Failed to install PyInstaller.
    exit /b 1
)

REM Build
echo [2/3] Building executable...
pyinstaller --onefile --windowed --name "WebGuardian" --icon assets\icon.ico --add-data "assets;assets" main.py
if %errorlevel% neq 0 (
    echo Error: Build failed.
    exit /b 1
)

echo [3/3] Done!
echo.
echo Executable created: dist\WebGuardian.exe
echo.
pause
