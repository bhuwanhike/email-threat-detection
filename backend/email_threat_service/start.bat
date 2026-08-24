@echo off
echo Installing Python dependencies...
pip install -r requirements.txt
echo.
echo Starting Email Threat Detection Backend on http://localhost:8000
uvicorn main:app --reload --host 0.0.0.0 --port 8000
