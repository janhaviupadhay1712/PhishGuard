@echo off
cd /d %~dp0
call .venv\Scripts\activate
python -m pip install pyinstaller
pyinstaller --onefile --name PhishGuardLauncher backend\app.py
pause
