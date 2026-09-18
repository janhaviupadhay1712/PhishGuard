# PhishGuard
Complete college major project for static phishing URL detection.

Real dataset: UCI PhiUSIIL Phishing URL Dataset, ID 967. 235,795 instances; 134,850 legitimate and 100,945 phishing. UCI label 1 is legitimate and 0 is phishing.

## Run on Windows
Run `run_windows.bat`. It creates the environment, installs dependencies, downloads the real dataset, trains Random Forest and starts `http://localhost:5000`.

## Manual
`python -m venv .venv` → activate → `pip install -r requirements.txt` → `python dataset/download_dataset.py` → `python -m backend.ml.train` → `python backend/app.py`.

## EXE
Run `build_exe.bat` on Windows after the above setup. It creates a Windows launcher executable with PyInstaller. A precompiled EXE is not included because this environment cannot install PyInstaller/build a Windows binary.

## Vercel
Vercel can host the frontend, but SQLite is not persistent in serverless deployments and scikit-learn artifacts can be deployment-size sensitive. For a robust deployment, host the Python API separately and use hosted Postgres for persistent history. The project includes the frontend as a single HTML file for easy deployment.

The system never opens submitted URLs and cannot guarantee safety.
