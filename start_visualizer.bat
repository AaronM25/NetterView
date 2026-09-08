@echo off
cd /d "C:\Users\aaron\NetScopeVisualizer"
py -3 -m venv venv
call venv\Scripts\activate.bat
python main.py
pause