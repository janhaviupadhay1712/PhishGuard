@echo off
title PhishGuard - Phishing URL Detection System
cd /d "%~dp0"

echo ==========================================
echo        PhishGuard
echo   Phishing URL Detection System
echo ==========================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [1/5] Creating Python virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Python is not installed or not available in PATH.
        pause
        exit /b 1
    )
) else (
    echo [1/5] Virtual environment already exists.
)

call ".venv\Scripts\activate.bat"

echo.
echo [2/5] Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo [3/5] Checking dataset...

if not exist "dataset\PhiUSIIL_Phishing_URL_Dataset.csv" (
    echo Dataset not found.
    echo Downloading PhiUSIIL dataset...
    python dataset\download_dataset.py

    if errorlevel 1 (
        echo ERROR: Dataset download failed.
        pause
        exit /b 1
    )
) else (
    echo Dataset already exists.
)

echo.
echo [4/5] Checking ML model...

if not exist "backend\ml\artifacts\model.joblib" (
    echo Model not found.
    echo Training Random Forest model...
    python -m backend.ml.train

    if errorlevel 1 (
        echo ERROR: Model training failed.
        pause
        exit /b 1
    )
) else (
    echo Trained model already exists.
)

echo.
echo [5/5] Starting PhishGuard...
echo.
echo ==========================================
echo   Server: http://127.0.0.1:5000
echo ==========================================
echo.
echo Press CTRL+C to stop the server.
echo.

python backend\app.py

echo.
echo PhishGuard has stopped.
pause