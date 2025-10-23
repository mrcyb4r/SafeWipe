# 🧹 SafeWipe — Mobile Secure Erase (Prototype)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Build-Prototype-orange)

---

**Author:** HARIOM SINGH (MR.Cyber)  
**GitHub:** [https://github.com/mrcyb4r/SafeWipe](https://github.com/mrcyb4r/SafeWipe)

---

### ⚠️ WARNING  
This tool can **irreversibly erase data**.  
Do **NOT** use on devices you do not own.  
Always test on a **spare or secondary phone** before using it on real devices.

---

## 🧠 Overview

**SafeWipe** is a **Python + PySide6** based GUI & CLI tool for securely wiping Android phones before resale.  
It helps ensure your data cannot be recovered — even using forensic tools — by guiding you through a safe wipe flow optimized for **non-root devices**.

---

## ✨ Features

- 🖥️ Sleek **PySide6 GUI** with dark hacker-style theme  
- 🔍 Automatic **ADB device detection**
- 📱 Quick system checks:
  - `ro.crypto.state` → Encryption status  
  - Root detection  
  - Installed apps summary  
- 🔒 Recommended Safe-Wipe Flow:
  1. Enable full-disk **encryption**
  2. Perform **factory reset**
  3. Verify post-wipe status  
- 🧪 **Dry-run mode** by default (no destructive actions)
- 🧾 Explicit **serial confirmation** required for wipe
- 📤 Export activity logs and reports
- 🧩 Cross-platform: **Windows**, **Linux**, **macOS**

---

## ⚙️ Requirements

- **Python 3.10+**
- **ADB (Android Platform Tools)** → [Download here](https://developer.android.com/studio/releases/platform-tools)
- Add `adb.exe` to your PATH or keep it beside the executable.

### Install dependencies
```bash
pip install PySide6 pyinstaller
🚀 Quick Start (Run from Source)
bash
Copy code
git clone https://github.com/mrcyb4r/SafeWipe.git
cd SafeWipe
python safewipe.py
✅ Make sure USB Debugging is enabled on your Android device.
Follow on-screen instructions to:

Detect connected device

View encryption & root status

Perform dry-run or confirmed secure wipe

🧱 Build Standalone EXE (Windows)
bash
Copy code
pyinstaller --onefile --windowed safewipe.py
This will create a portable SafeWipe.exe in the dist/ folder.
Copy these files next to it for full functionality:

Copy code
adb.exe
AdbWinApi.dll
AdbWinUsbApi.dll
🧩 CLI Mode (Coming Soon)
For command-line use:

bash
Copy code
python safewipe.py --cli --dry-run
📜 License
Open-source under the MIT License

🔗 Repository
GitHub → https://github.com/mrcyb4r/SafeWipe

🧠 Credits
Developed by HARIOM SINGH (MR.Cyber)
Cyber Expert • EbhartSec • Digital Forensics & Mobile Security Researcher
