@echo off
REM Xiaomi HyperOS BL Unlock Bypass Script
REM Temporarily modifies build properties to bypass community level check
echo ==========================================
echo Xiaomi HyperOS BL Unlock Bypass
echo ==========================================
echo.
echo Step 1: Check device connection...
adb devices
echo.
echo Step 2: Check current build version...
adb shell getprop ro.build.version.incremental
adb shell getprop ro.build.version.release
echo.
echo Step 3: Attempting to bypass...
echo This script will try to bind the Xiaomi account.
echo If it fails, try the alternative method below.
echo.
echo Method A: Standard bypass
adb shell setprop ro.build.version.incremental "MIUI-14.0.1.0.TMOCNXM"
adb shell setprop ro.build.version.release "13"
echo.
echo Now go to phone Settings ^> Developer Options ^> Device Unlock Status
echo and try to bind your account.
echo.
echo If the bind button is grayed out, try Method B:
echo.
echo Method B: System Settings downgrade (for HyperOS-native devices)
echo 1. Download the modified Settings APK from the link below
echo 2. adb install -r --bypass-low-target-sdk-block Settings.apk
echo 3. Reboot phone
echo 4. Retry binding
echo.
pause
