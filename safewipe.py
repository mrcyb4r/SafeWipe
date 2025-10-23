"""
SafeWipe GUI - Advanced (Non-Root Focused)

Enhancements:
- Recommended Safe Wipe (Non-Root) flow: quick-check -> encryption guidance -> factory reset -> verify reconnection
- Button to open Security settings on device to enable encryption
- Double-reset guidance (re-encrypt then reset) and verification of ro.crypto.state after reconnection
- Dry-run default and strict serial confirmation for destructive actions
- Improved logs and user guidance for non-technical users

Requirements:
- Python 3.10+
- PySide6 (pip install PySide6)
- adb in PATH (Android Platform Tools)
"""

import sys
import subprocess
import datetime
from pathlib import Path
from time import sleep

from PySide6 import QtCore, QtGui, QtWidgets

APP_TITLE = "SafeWipe - Mobile Secure Erase (Hariom Singh) - NonRoot Flow"

# ---------------------- Helper functions ----------------------
def run_cmd(cmd, timeout=60):
    """Run a command (list) and return (rc, stdout, stderr). Handles strings lists."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode(errors='ignore'), err.decode(errors='ignore')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -9, '', 'timeout'
    except FileNotFoundError as e:
        return -2, '', f'cmd not found: {e}'
    except Exception as e:
        return -1, '', str(e)

# ---------------------- Worker Threads ----------------------
class WorkerSignals(QtCore.QObject):
    finished = QtCore.Signal()
    progress = QtCore.Signal(str)
    error = QtCore.Signal(str)

class CommandWorker(QtCore.QRunnable):
    def __init__(self, cmd_list, signals: WorkerSignals, per_cmd_timeout=60):
        super().__init__()
        self.cmd_list = cmd_list
        self.signals = signals
        self.per_cmd_timeout = per_cmd_timeout

    def run(self):
        try:
            for cmd in self.cmd_list:
                try:
                    display = " ".join(cmd)
                except Exception:
                    display = str(cmd)
                self.signals.progress.emit(f"Running: {display}")
                rc, out, err = run_cmd(cmd, timeout=self.per_cmd_timeout)
                if out:
                    self.signals.progress.emit(out.strip())
                if err:
                    # avoid flooding logs with blanks
                    if err.strip():
                        self.signals.progress.emit(err.strip())
                if rc != 0:
                    self.signals.error.emit(f"Command failed: {display} -> rc={rc}")
                    return
            self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(str(e))

# ---------------------- Main Window ----------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1000, 700)
        self.setStyleSheet(self.dark_style())

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_v = QtWidgets.QVBoxLayout(central)

        # Header
        hdr = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel('<b style="font-size:18pt; color:#7CFFB2">SafeWipe</b> <span style="color:#9bd">— Mobile Secure Erase</span>')
        hdr.addWidget(title)
        hdr.addStretch()
        author = QtWidgets.QLabel('<i>by HARIOM SINGH</i>')
        hdr.addWidget(author)
        main_v.addLayout(hdr)

        # Split: left controls, right info/logs
        split = QtWidgets.QHBoxLayout()
        left = QtWidgets.QFrame(); left.setMinimumWidth(380)
        left.setLayout(QtWidgets.QVBoxLayout())

        # Device group
        dev_group = QtWidgets.QGroupBox("Device Connection")
        g = QtWidgets.QVBoxLayout()
        self.lbl_status = QtWidgets.QLabel("No device detected")
        g.addWidget(self.lbl_status)
        btn_h = QtWidgets.QHBoxLayout()
        self.btn_detect = QtWidgets.QPushButton("Detect (ADB)")
        self.btn_detect.clicked.connect(self.detect_adb_devices)
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.detect_adb_devices)
        btn_h.addWidget(self.btn_detect); btn_h.addWidget(self.btn_refresh)
        g.addLayout(btn_h)
        self.lst_devices = QtWidgets.QListWidget()
        g.addWidget(self.lst_devices)
        # helper buttons
        self.btn_open_security = QtWidgets.QPushButton("Open Security Settings (Help enable encryption)")
        self.btn_open_security.clicked.connect(self.open_security_settings)
        g.addWidget(self.btn_open_security)
        dev_group.setLayout(g)
        left.layout().addWidget(dev_group)

        # Wipe options group
        wipe_group = QtWidgets.QGroupBox("Wipe / Recovery Options")
        wg = QtWidgets.QFormLayout()
        self.cmb_method = QtWidgets.QComboBox()
        self.cmb_method.addItems([
            "Factory Reset (quick)",
            "Overwrite userdata (requires root) - template",
            "Secure-erase (vendor tool / flashing) - manual"
        ])
        wg.addRow("Method:", self.cmb_method)
        self.chk_dry = QtWidgets.QCheckBox("Dry-run (no destructive commands) — default ON")
        self.chk_dry.setChecked(True)
        wg.addRow(self.chk_dry)

        # Buttons: quick-check, recommended-wipe, start-wipe, verify
        self.btn_quick = QtWidgets.QPushButton("Quick Safety Check")
        self.btn_quick.clicked.connect(self.quick_safety_check)
        self.btn_recommended = QtWidgets.QPushButton("Recommended Safe Wipe (Non-Root)")
        self.btn_recommended.setToolTip("Best practice for non-root phones: encryption -> factory reset -> verify")
        self.btn_recommended.clicked.connect(self.recommended_safe_wipe)
        self.btn_wipe = QtWidgets.QPushButton("Start Wipe (destructive)")
        self.btn_wipe.clicked.connect(self.start_wipe)
        self.btn_verify = QtWidgets.QPushButton("Verify / Check After Wipe")
        self.btn_verify.clicked.connect(self.verify_device)

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.btn_quick)
        btn_row.addWidget(self.btn_recommended)
        wg.addRow(btn_row)
        wg.addRow(self.btn_wipe)
        wg.addRow(self.btn_verify)

        wipe_group.setLayout(wg)
        left.layout().addWidget(wipe_group)

        # Tips / instructions
        instr = QtWidgets.QGroupBox("Instructions (Non-Root flow)")
        il = QtWidgets.QVBoxLayout()
        self.lbl_instr = QtWidgets.QLabel(
            "1) Connect phone & enable USB Debugging.\n"
            "2) Use 'Quick Safety Check'. If UNENCRYPTED → press 'Open Security Settings' and enable encryption.\n"
            "3) After encryption is enabled, run 'Recommended Safe Wipe'.\n"
            "4) When device reboots, reconnect and press 'Verify'."
        )
        self.lbl_instr.setWordWrap(True)
        il.addWidget(self.lbl_instr)
        instr.setLayout(il)
        left.layout().addWidget(instr)

        left.layout().addStretch()
        split.addWidget(left)

        # Right side: info + logs
        right = QtWidgets.QFrame()
        right.setLayout(QtWidgets.QVBoxLayout())
        info_box = QtWidgets.QGroupBox("Device Info / Quick Report")
        info_layout = QtWidgets.QVBoxLayout()
        self.txt_info = QtWidgets.QPlainTextEdit()
        self.txt_info.setReadOnly(True)
        info_layout.addWidget(self.txt_info)
        info_box.setLayout(info_layout)
        right.layout().addWidget(info_box)

        log_box = QtWidgets.QGroupBox("Activity Log")
        log_layout = QtWidgets.QVBoxLayout()
        self.txt_log = QtWidgets.QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QtGui.QFont("Consolas", 10))
        log_layout.addWidget(self.txt_log)
        log_box.setLayout(log_layout)
        right.layout().addWidget(log_box)

        split.addWidget(right, 2)
        main_v.addLayout(split)

        # Threadpool
        self.pool = QtCore.QThreadPool()

        # state
        self.last_report = None

        # initial detect
        QtCore.QTimer.singleShot(200, self.detect_adb_devices)

    # ---------------------- UI helpers ----------------------
    def dark_style(self):
        return """
        QWidget { background-color: #061018; color: #cfeeea; font-family: Arial; }
        QGroupBox { border: 1px solid #0b6; margin-top: 6px; }
        QGroupBox::title { color:#9df; padding: 2px 6px; }
        QPushButton { background: #092; border: 1px solid #1f6; padding:6px; }
        QPushButton:hover { background: #0b3; }
        QListWidget, QPlainTextEdit { background: #021018; color: #cfeeea; }
        QLabel { color:#9bd; }
        """

    def log(self, msg: str):
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{t}] {msg}"
        try:
            self.txt_log.appendPlainText(line)
        except Exception:
            print(line)

    # ---------------------- ADB helpers ----------------------
    def detect_adb_devices(self):
        self.log("Detecting adb devices...")
        rc, out, err = run_cmd(["adb", "devices"])
        if rc == -2:
            self.lbl_status.setText("adb not found in PATH. Install platform-tools.")
            self.log(err or "adb missing")
            return
        if rc != 0:
            self.lbl_status.setText("adb present but returned error.")
            self.log(err or out or f"rc={rc}")
            return
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        devs = []
        # skip header line if present
        for l in lines[1:]:
            parts = l.split()
            if len(parts) >= 2:
                devs.append((parts[0], parts[1]))
        self.lst_devices.clear()
        if not devs:
            self.lbl_status.setText("No devices detected. Enable USB Debugging & authorize PC.")
            self.log("No adb devices")
            return
        self.lbl_status.setText(f"{len(devs)} device(s) detected")
        for s, st in devs:
            self.lst_devices.addItem(f"{s} [{st}]")
        self.log(f"Found {len(devs)} device(s)")

    def selected_serial(self):
        it = self.lst_devices.currentItem()
        if not it:
            return None
        return it.text().split()[0]

    # ---------------------- Quick checks ----------------------
    def quick_safety_check(self):
        serial = self.selected_serial()
        if not serial:
            QtWidgets.QMessageBox.warning(self, "No device", "Select a connected Android device first.")
            return
        self.log(f"Quick Safety Check for {serial} started.")
        cmds = [
            ["adb", "-s", serial, "shell", "getprop", "ro.build.fingerprint"],
            ["adb", "-s", serial, "shell", "getprop", "ro.crypto.state"],
            ["adb", "-s", serial, "shell", "getprop", "ro.boot.verifiedbootstate"],
            ["adb", "-s", serial, "shell", "wm", "size"],
            ["adb", "-s", serial, "shell", "df", "/data"],
            ["adb", "-s", serial, "shell", "pm", "list", "packages", "-3"],
            ["adb", "-s", serial, "shell", "which", "su"],
        ]
        signals = WorkerSignals()
        signals.progress.connect(self.log)
        signals.error.connect(lambda e: self.log("ERROR: " + e))
        signals.finished.connect(lambda: self.log("Quick check finished."))
        worker = CommandWorker(cmds, signals, per_cmd_timeout=15)
        self.pool.start(worker)

        # also set info panel (non-blocking guidance)
        self.txt_info.setPlainText(f"""Quick Check started for {serial}.
See Activity Log for detailed outputs.

Recommendations:
- If ro.crypto.state != 'encrypted' then enable device encryption before factory reset.
- If 'su' binary present, device appears rooted — overwrite methods require caution.
- If many unknown user apps exist, consider factory reset + reflash stock firmware.
""")

    # ---------------------- Helpers to open settings ----------------------
    def open_security_settings(self):
        serial = self.selected_serial()
        if not serial:
            QtWidgets.QMessageBox.warning(self, "No device", "Select a connected Android device first.")
            return
        # Try to open security settings on the device to let user enable encryption
        rc, out, err = run_cmd(["adb", "-s", serial, "shell", "am", "start", "-a", "android.settings.SECURITY_SETTINGS"])
        if rc != 0:
            QtWidgets.QMessageBox.warning(self, "Failed", "Could not open Security Settings. Open manually on device.")
            self.log(err or out or "open_security failed")
        else:
            self.log("Opened Security Settings on device. Please enable encryption (if available) following device prompts.")

    # ---------------------- Recommended Safe Wipe (Non-root) ----------------------
    def recommended_safe_wipe(self):
        """Automate best-effort non-root safe wipe: check encryption -> guide to enable -> factory reset -> wait+verify"""
        serial = self.selected_serial()
        if not serial:
            QtWidgets.QMessageBox.warning(self, "No device", "Select a device first.")
            return

        dry = self.chk_dry.isChecked()

        # Step 1: quick read of encryption state
        rc, enc_state, err = run_cmd(["adb", "-s", serial, "shell", "getprop", "ro.crypto.state"], timeout=8)
        enc_state = (enc_state or "").strip().lower()
        self.log(f"Encryption state: '{enc_state}'")

        if enc_state != "encrypted":
            # Not encrypted -> guide user to enable encryption
            msg = (
                "Device appears UNENCRYPTED.\n\n"
                "Best practice for non-root phones:\n"
                "1) Enable device encryption from Security settings (this may take time).\n"
                "2) After encryption completes, perform factory reset.\n\n"
                "Do you want the tool to open Security Settings on the device now?"
            )
            res = QtWidgets.QMessageBox.question(self, "Encryption required", msg,
                                                 QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if res == QtWidgets.QMessageBox.Yes:
                self.open_security_settings()
                QtWidgets.QMessageBox.information(self, "Next", "Enable encryption on the device, then reconnect and run 'Recommended Safe Wipe' again.")
                return
            else:
                QtWidgets.QMessageBox.information(self, "Abort", "Recommended flow requires encryption. Aborting.")
                return
        else:
            # Encrypted -> proceed to factory reset step
            confirm_msg = (
                "Device appears encrypted. Recommended next step is Factory Reset.\n\n"
                "This action is DESTRUCTIVE and irreversible.\n\n"
                f"Dry-run is {'ON' if dry else 'OFF'}. "
                "If Dry-run is ON, commands will not run.\n\n"
                "Type device serial exactly to confirm destructive action:"
            )
            if not dry:
                text, ok = QtWidgets.QInputDialog.getText(self, "Confirm destructive action", confirm_msg)
                if not ok or text.strip() != serial:
                    QtWidgets.QMessageBox.warning(self, "Cancelled", "Serial confirmation failed. Aborting.")
                    self.log("User failed serial confirmation for destructive action.")
                    return
            else:
                # still ask a simple ok
                ok = QtWidgets.QMessageBox.question(self, "Confirm (Dry-run)", "Proceed with factory-reset (DRY-RUN)?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
                if ok != QtWidgets.QMessageBox.Yes:
                    self.log("User cancelled dry-run factory-reset")
                    return

            # perform factory reset (or dry-run)
            if dry:
                self.log(f"[DRY-RUN] Would run: adb -s {serial} shell am broadcast -a android.intent.action.MASTER_CLEAR")
                QtWidgets.QMessageBox.information(self, "Dry-run", "Factory reset was simulated (dry-run). Uncheck Dry-run to perform real wipe.")
                return
            else:
                self.log("Issuing factory reset broadcast (may be device-specific).")
                rc, out, err = run_cmd(["adb", "-s", serial, "shell", "am", "broadcast", "-a", "android.intent.action.MASTER_CLEAR"], timeout=20)
                if rc != 0:
                    # try alternative: reboot to recovery and do wipe_data (attempt)
                    self.log(f"Factory-reset broadcast failed (rc={rc}), attempting reboot recovery wipe_data. err={err or out}")
                    rc2, o2, e2 = run_cmd(["adb", "-s", serial, "reboot", "recovery"], timeout=10)
                    # Can't fully automate recovery menu; instruct user
                    QtWidgets.QMessageBox.information(self, "Manual step",
                                                      "Device was rebooted to recovery. Please perform 'wipe data/factory reset' on the device's recovery menu if needed.")
                else:
                    self.log("Factory reset command sent. Device will reboot and erase data.")

                # After issuing reset, wait for device to disconnect/reconnect
                QtWidgets.QMessageBox.information(self, "Wait", "Device will reboot and perform factory reset. After the device shows setup screen, reconnect it and press 'Verify'.")
                return

    # ---------------------- Start Wipe (manual command) ----------------------
    def start_wipe(self):
        serial = self.selected_serial()
        if not serial:
            QtWidgets.QMessageBox.warning(self, "No device", "Select a device first.")
            return
        method = self.cmb_method.currentText()
        dry = self.chk_dry.isChecked()

        # require typing serial for destructive
        if not dry:
            text, ok = QtWidgets.QInputDialog.getText(self, "Confirm destructive action", f"Type serial to confirm: {serial}")
            if not ok or text.strip() != serial:
                QtWidgets.QMessageBox.warning(self, "Cancelled", "Serial confirmation failed.")
                return
        else:
            ok = QtWidgets.QMessageBox.question(self, "Proceed (Dry-run)", "Proceed in dry-run mode?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if ok != QtWidgets.QMessageBox.Yes:
                return

        cmds = []
        if "Factory Reset" in method:
            if dry:
                self.log(f"[DRY-RUN] Would factory-reset {serial}")
            else:
                cmds.append(["adb", "-s", serial, "shell", "am", "broadcast", "-a", "android.intent.action.MASTER_CLEAR"])
        elif "Overwrite userdata" in method:
            # overwrite requires root - notify user
            rc, out, err = run_cmd(["adb", "-s", serial, "shell", "which", "su"], timeout=5)
            if rc == 0 and out.strip():
                if dry:
                    self.log(f"[DRY-RUN] Would overwrite userdata on {serial} (root detected).")
                else:
                    cmds.append(["adb", "-s", serial, "shell", "su", "-c", "dd if=/dev/urandom of=/dev/block/by-name/userdata bs=4096"])
            else:
                QtWidgets.QMessageBox.warning(self, "No root", "Device does not appear rooted. Overwrite option requires root. Use recommended non-root flow.")
                return
        elif "Secure-erase" in method:
            QtWidgets.QMessageBox.information(self, "Manual step", "Secure-erase requires vendor-specific tool/flash. Use manufacturer flashing tools (Odin/fastboot/Qualcomm) outside this tool.")
            return

        if cmds:
            signals = WorkerSignals()
            signals.progress.connect(self.log)
            signals.error.connect(lambda e: self.log("ERROR: " + e))
            signals.finished.connect(lambda: self.log("Commands finished."))
            worker = CommandWorker(cmds, signals, per_cmd_timeout=60)
            self.pool.start(worker)

    # ---------------------- Verify & Export ----------------------
    def verify_device(self):
        serial = self.selected_serial()
        if not serial:
            QtWidgets.QMessageBox.warning(self, "No device", "Select a device first.")
            return
        # Basic check for /data listing and crypto state
        self.log(f"Verifying device {serial} ...")
        rc1, out1, err1 = run_cmd(["adb", "-s", serial, "shell", "getprop", "ro.crypto.state"], timeout=8)
        rc2, out2, err2 = run_cmd(["adb", "-s", serial, "shell", "ls", "-la", "/data"], timeout=8)
        out1 = (out1 or "").strip()
        if rc1 != 0:
            self.log(f"Could not read ro.crypto.state: {err1 or out1}")
        else:
            self.log(f"ro.crypto.state = {out1}")
        if rc2 != 0:
            self.log(f"Listing /data failed (may be locked or permission limited): {err2 or out2}")
        else:
            self.log(f"/data listing:\n{out2}")

        # Update info panel
        self.txt_info.setPlainText(f"Verify results for {serial}:\nro.crypto.state = {out1}\n\nSee Activity Log for /data listing (may be limited).")

    def export_report(self):
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save report", str(Path.home() / "safewipe_report.txt"), "Text Files (*.txt)")
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(self.txt_log.toPlainText())
            QtWidgets.QMessageBox.information(self, "Saved", f"Report saved to {fn}")
            self.log(f"Report exported to {fn}")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Save failed", str(e))

# ---------------------- App entry ----------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
