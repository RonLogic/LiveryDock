@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto :dependencies
where py >nul 2>nul
if errorlevel 1 goto :python
py -3 -m venv .venv
if errorlevel 1 goto :error
goto :dependencies
:python
where python >nul 2>nul
if errorlevel 1 goto :no_python
python -m venv .venv
if errorlevel 1 goto :error
:dependencies
".venv\Scripts\python.exe" -c "import sys; assert sys.version_info >= (3,11); import tkinter" >nul 2>nul
if errorlevel 1 goto :no_python
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -e .
if errorlevel 1 goto :error
start "" ".venv\Scripts\pythonw.exe" "%~dp0main.pyw" %*
exit /b 0
:no_python
echo Install Python 3.11 or newer with Tkinter and the Python launcher, then try again.
pause
exit /b 1
:error
echo LiveryDock setup failed. Check the error above and your internet connection.
pause
exit /b 1
