@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto :build
py -3 -m venv .venv
if errorlevel 1 goto :error
:build
".venv\Scripts\python.exe" -m pip install -e ".[dev]"
if errorlevel 1 goto :error
".venv\Scripts\python.exe" -m pytest
if errorlevel 1 goto :error
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean LiveryDock.spec
if errorlevel 1 goto :error
".venv\Scripts\python.exe" tools\package_release.py
if errorlevel 1 goto :error
echo Build complete: dist\LiveryDock.exe and release packages.
pause
exit /b 0
:error
echo Build failed. Review the error above.
pause
exit /b 1
