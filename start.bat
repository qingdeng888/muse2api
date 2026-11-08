@echo off
rem muse2api local launcher (all paths on E:, nothing written to C:)
cd /d %~dp0
set PIP_CACHE_DIR=%~dp0.pip-cache
set TMP=%~dp0.tmp
set TEMP=%~dp0.tmp
if not exist ".tmp" mkdir ".tmp"
echo [muse2api] starting on http://127.0.0.1:30086 ...
"venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port 30086
pause
