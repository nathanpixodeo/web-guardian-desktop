#!/bin/bash
# =============================================
# Build WebGuardian Desktop for Linux
# =============================================
set -e

echo "Building WebGuardian Desktop for Linux..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 not found. Please install Python 3.10+."
    exit 1
fi

# Install dependencies
echo "[1/3] Installing dependencies..."
pip3 install -r requirements.txt

# Install PyInstaller
pip3 install pyinstaller

# Build
echo "[2/3] Building executable..."
pyinstaller --noconfirm --clean --onefile --windowed --name "WebGuardian" --add-data "assets:assets" main.py

echo "[3/3] Done!"
echo ""
echo "Executable created: dist/WebGuardian"
echo ""
