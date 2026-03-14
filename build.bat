@echo off
:: Dimedropper — one-click build script
:: Produces dist\dimedropper.exe
:: Requires Python and pip on PATH.

echo ============================================
echo  Dimedropper build
echo ============================================

:: Install / upgrade build tools
pip install --upgrade pyinstaller pillow pystray psutil

:: Build
pyinstaller dimedropper.spec --clean --noconfirm

echo.
if exist dist\dimedropper.exe (
    echo  Build succeeded: dist\dimedropper.exe
) else (
    echo  Build FAILED — check output above.
    exit /b 1
)
