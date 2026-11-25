@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
  echo Missing .venv. Create it and install requirements.txt first.
  exit /b 1
)
".venv\Scripts\python.exe" "training\url_pipeline.py" collect --phish-only
exit /b %ERRORLEVEL%
