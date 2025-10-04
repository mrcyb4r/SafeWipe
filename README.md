# SafeWipe
Secure mobile data wipe tool (GUI + CLI) for safe resale — prevents forensic recovery after factory reset. Built with Python &amp; PySide6.

# SafeWipe — Mobile Secure Erase (Prototype)

**Author:** HARIOM SINGH  
**Purpose:** A GUI tool to help ordinary users securely wipe Android phones (non-root focused flow).  
**WARNING:** This tool can irreversibly erase data. **Do not use on devices you do not own.** Always test on spare devices first.

## Features
- PySide6 GUI with dark "hacker" theme.
- ADB-based detection and quick checks (`ro.crypto.state`, root detection, packages).
- Recommended safe-wipe flow for non-root devices: **Enable encryption → Factory Reset → Verify**.
- Dry-run default; destructive actions require explicit serial confirmation.
- Export activity report.

## Requirements (for development)
- Python 3.10+  
- PySide6 (`pip install PySide6`)  
- PyInstaller (for building exe): `pip install pyinstaller`  
- adb (Android Platform Tools) — place `adb.exe` with the exe or in PATH.

## Quick usage
1. Connect device with USB Debugging enabled.  
2. Run locally:
   ```bash
   python safewipe.py

