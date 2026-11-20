@echo off
REM ============================================================
REM  Build Deep Remover thanh 1 file EXE (chay san quyen Admin)
REM  Yeu cau: da cai Python 3 tren Windows
REM ============================================================
echo [1/2] Cai PyInstaller (neu chua co)...
pip install pyinstaller

echo [2/2] Dang build...
pyinstaller --onefile --noconsole --uac-admin --name "DeepRemover" ^
  --version-file= DeepRemover.py

echo.
echo === XONG ===
echo File exe nam trong thu muc: dist\DeepRemover.exe
pause
