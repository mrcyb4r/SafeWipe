# 🧹 SafeWipe — Mobile Secure Erase (Prototype)

**Author:** HARIOM SINGH (MR.Cyber)  
**Purpose:** A GUI + CLI tool to help ordinary users securely wipe Android phones before resale — designed to prevent **forensic recovery** even after factory reset.

⚠️ **WARNING:**  
This tool can irreversibly erase data. Do **NOT** use it on devices you don’t own.  
Always test first on spare / old devices.

---

## 🧠 Overview

SafeWipe is a **Python + PySide6** based GUI tool that performs secure mobile data wiping operations using **ADB** (Android Debug Bridge).  
It focuses on **non-root** Android devices — helping ensure data safety and privacy before resale.

---

## ✨ Features

- 🖥️ PySide6 GUI with dark **hacker-style theme**
- 🔍 Automatic ADB detection of connected devices
- 📱 Quick checks:  
  - `ro.crypto.state` (encryption status)  
  - Root detection  
  - Installed package summary
- 🔒 Recommended Safe-Wipe Flow for **non-root** phones:
  1. Enable full-disk **encryption**
  2. Perform **factory reset**
  3. Verify post-wipe status
- 🧪 **Dry-run mode** by default (no destructive action)
- 🧾 Destructive actions require explicit **serial confirmation**
- 📤 Export activity logs or reports
- ⚙️ Works on Windows, Linux, and macOS

---

## ⚙️ Requirements

- **Python 3.10+**
- **ADB (Android Platform Tools)** — download from  
  [https://developer.android.com/studio/releases/platform-tools](https://developer.android.com/studio/releases/platform-tools)
- Add `adb.exe` to your PATH or place it next to the built exe.
- **Dependencies:**
  ```bash
  pip install PySide6
  pip install pyinstaller
🚀 Quick Start (Run from Source)
Clone the repository:

git clone https://github.com/mrcyb4r/SafeWipe.git
cd SafeWipe
Connect your Android device with USB Debugging enabled.

Run the tool:


git clone https://github.com/mrcyb4r/SafeWipe.git
cd SafeWipe
python safewipe.py

Follow on-screen steps to:

Detect device

View status

Start secure wipe (dry-run or confirmed mode)

🧱 Build Standalone EXE (Windows)
If you want to create a standalone executable:


pyinstaller --onefile --windowed safewipe.py
This will create a portable SafeWipe.exe in the dist/ folder.
Copy adb.exe, AdbWinApi.dll, and AdbWinUsbApi.dll next to it for full functionality.


📜 License
This project is open-source under the MIT License.

🔗 Repository
GitHub: https://github.com/mrcyb4r/SafeWipe

🧠 Credits
Developed by HARIOM SINGH (MR.Cyber)
Cyber Expert | EbhartSec | Digital Forensics & Mobile Security Researcher

   git add README.md
   git commit -m "Added detailed project README"
   git push origin main
Would you like me to also create a GitHub badges header section (like Python version, stars, license, build status) for the top of your README?
