$ErrorActionPreference = "Stop"
python tools\validate.py
python tools\build.py --compiler offline-demo --output ..\MS-Sentinel
python tools\verify_output.py ..\MS-Sentinel
python -m unittest discover -s tests -v
Write-Host "Demo build complete. Open ..\MS-Sentinel\Clients and ..\MS-Sentinel\_build\build-manifest.json"
