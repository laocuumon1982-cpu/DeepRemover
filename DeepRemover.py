# -*- coding: utf-8 -*-
"""
==========================================================================
 Deep Remover by Duy Anh  -  Gỡ sạch triệt để phần mềm trên Windows
==========================================================================
 Quét sâu + gỡ triệt để: tiến trình ngầm, dịch vụ, driver kernel tự bảo vệ,
 Scheduled Tasks, Registry, file/thư mục rác. Tích hợp Chặn / Cho phép cài lại
 qua cơ chế IFEO (Image File Execution Options).

 Mục tiêu: 360 Total Security, WPS Office, Avast Antivirus, Norton AntiVirus,
           BKAV, McAfee, Avast Free Antivirus, AVG AntiVirus.

 * Yêu cầu: Windows, chạy quyền Administrator (tool tự xin nâng quyền UAC).
 * Dữ liệu log/lịch sử: SQLite (deep_remover.db) - tự import JSON cũ nếu có.
 * Cấu hình: config.json (sửa tay được).
 * Build 1 file exe:  pyinstaller --onefile --noconsole --uac-admin DeepRemover.py
==========================================================================
"""

import os
import sys
import json
import time
import ctypes
import shutil
import sqlite3
import datetime
import threading
import subprocess

# ------------------------------------------------------------------ Tkinter
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

APP_NAME    = "Deep Remover by Duy Anh"
APP_VERSION = "1.0.0"
BASE_DIR    = os.path.dirname(os.path.abspath(sys.argv[0]))
DB_PATH     = os.path.join(BASE_DIR, "deep_remover.db")
CFG_PATH    = os.path.join(BASE_DIR, "config.json")

# Cửa sổ ẩn console cho subprocess
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# MoveFileEx flag: xóa khi reboot
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4


# ==========================================================================
#  CSDL sản phẩm cần gỡ  -  "chữ ký" từng thành phần
#  (processes, services, drivers, task keywords, reg keys, paths, uninstall
#   name match, và exe cần chặn IFEO)
# ==========================================================================
PRODUCTS = {
    "360 Total Security": {
        "processes": ["360Tray.exe", "360Safe.exe", "ZhuDongFangYu.exe", "360sd.exe",
                      "QHActiveDefense.exe", "360rp.exe", "LiveUpdate360.exe",
                      "360SPTool.exe", "360leakfixer.exe", "360EntClient.exe",
                      "360bdoctor.exe", "360speedld.exe", "wsctrl.exe"],
        "services":  ["360rp", "360safe", "ZhuDongFangYu", "QHActiveDefense",
                      "360EntMiscSvc", "360SPSvc", "360SvcMgr", "360WebShield"],
        "drivers":   ["360AntiHacker", "360AvFlt", "360Box360", "360FsFlt",
                      "360netmon", "360qpesv", "BAPIDRV", "360SelfProtection",
                      "dnf1000", "360Camera"],
        "task_kw":   ["360"],
        "reg_keys":  [r"HKLM\SOFTWARE\360Safe",
                      r"HKLM\SOFTWARE\360",
                      r"HKLM\SOFTWARE\WOW6432Node\360Safe",
                      r"HKLM\SOFTWARE\WOW6432Node\360",
                      r"HKCU\SOFTWARE\360Safe",
                      r"HKCU\SOFTWARE\360"],
        "paths":     [r"%ProgramFiles(x86)%\360",
                      r"%ProgramFiles%\360",
                      r"%ProgramData%\360safe",
                      r"%ProgramData%\360Security",
                      r"%LOCALAPPDATA%\360Chrome",
                      r"%LOCALAPPDATA%\360se6"],
        "uninstall_match": ["360 total security", "360 total", "360safe"],
        "ifeo_exe":  ["360Safe.exe", "360Tray.exe", "360sd.exe", "360Setup.exe",
                      "inst.exe", "QHInstaller.exe", "360TotalSecurity.exe",
                      "360base.exe"],
    },

    "WPS Office": {
        "processes": ["wps.exe", "et.exe", "wpp.exe", "wpscloudsvr.exe",
                      "wpscenter.exe", "ksolaunch.exe", "wpsupdate.exe",
                      "wtoolex.exe", "ksomisc.exe", "wpsnotify.exe",
                      "pofficeservice.exe", "wpsoffice.exe"],
        "services":  ["wpscloudsvr", "KWPSService", "WpsUpdateService"],
        "drivers":   [],
        "task_kw":   ["wps", "kingsoft"],
        "reg_keys":  [r"HKLM\SOFTWARE\Kingsoft",
                      r"HKLM\SOFTWARE\WOW6432Node\Kingsoft",
                      r"HKCU\SOFTWARE\Kingsoft",
                      r"HKCU\SOFTWARE\kingsoft"],
        "paths":     [r"%ProgramFiles%\Kingsoft",
                      r"%ProgramFiles(x86)%\Kingsoft",
                      r"%ProgramData%\Kingsoft",
                      r"%LOCALAPPDATA%\Kingsoft",
                      r"%APPDATA%\Kingsoft",
                      r"%ProgramData%\kingsoft"],
        "uninstall_match": ["wps office", "kingsoft"],
        "ifeo_exe":  ["wps.exe", "wpssetup.exe", "wps_office_setup.exe",
                      "ksomisc.exe", "wpsupdate.exe"],
    },

    "Avast Antivirus": {
        "processes": ["AvastUI.exe", "AvastSvc.exe", "aswidsagent.exe",
                      "aswEngSrv.exe", "afwServ.exe", "wsc_proxy.exe",
                      "AvastBrowser.exe", "overseer.exe", "AvastBrowserUpdate.exe"],
        "services":  ["avast Antivirus", "aswbIDSAgent", "avast! Firewall",
                      "AvastWscReporter", "AvastVBoxSvc", "aswEngSrv"],
        "drivers":   ["aswArPot", "aswbidsdriver", "aswbidsh", "aswbuniv",
                      "aswSnx", "aswSP", "aswStm", "aswVmm", "aswNetHub",
                      "aswRdr2", "aswSP_WFP", "aswKbd", "aswRvrt", "aswHdsKe",
                      "aswMonFlt", "aswElam"],
        "task_kw":   ["avast"],
        "reg_keys":  [r"HKLM\SOFTWARE\Avast Software",
                      r"HKLM\SOFTWARE\WOW6432Node\Avast Software",
                      r"HKLM\SOFTWARE\AVAST Software",
                      r"HKCU\SOFTWARE\Avast Software"],
        "paths":     [r"%ProgramFiles%\Avast Software",
                      r"%ProgramFiles(x86)%\Avast Software",
                      r"%ProgramData%\Avast Software",
                      r"%ProgramData%\AvastFreeAntivirusSetup"],
        "uninstall_match": ["avast antivirus", "avast free antivirus", "avast premium"],
        "ifeo_exe":  ["AvastUI.exe", "instup.exe", "Avast_setup.exe",
                      "avast_free_antivirus_setup_online.exe",
                      "avast_free_antivirus_setup.exe", "AvastBrowserSetup.exe"],
    },

    "Avast Free Antivirus": {
        # Dùng chung engine với Avast Antivirus - giữ riêng để chặn IFEO/uninstall match riêng
        "processes": ["AvastUI.exe", "AvastSvc.exe", "aswidsagent.exe",
                      "afwServ.exe", "wsc_proxy.exe"],
        "services":  ["avast Antivirus", "aswbIDSAgent", "AvastWscReporter"],
        "drivers":   ["aswArPot", "aswbidsdriver", "aswSnx", "aswSP", "aswStm",
                      "aswVmm", "aswNetHub", "aswRdr2", "aswMonFlt"],
        "task_kw":   ["avast free", "avast"],
        "reg_keys":  [r"HKLM\SOFTWARE\Avast Software",
                      r"HKLM\SOFTWARE\WOW6432Node\Avast Software"],
        "paths":     [r"%ProgramFiles%\Avast Software",
                      r"%ProgramData%\Avast Software"],
        "uninstall_match": ["avast free antivirus"],
        "ifeo_exe":  ["AvastUI.exe", "avast_free_antivirus_setup_online.exe",
                      "avast_free_antivirus_setup.exe", "instup.exe"],
    },

    "AVG AntiVirus": {
        "processes": ["AVGUI.exe", "avgsvc.exe", "avgToolsSvc.exe",
                      "aswidsagenta.exe", "AVGSvc.exe", "avgwdsvc.exe",
                      "AVGBrowser.exe"],
        "services":  ["avgAntivirus", "avgbIDSAgent", "avgNetHub",
                      "avgWscReporter", "AVG Antivirus", "avgToolsSvc"],
        "drivers":   ["avgArPot", "avgbidsdriver", "avgbidsh", "avgbuniv",
                      "avgSnx", "avgSP", "avgStm", "avgVmm", "avgNetHub",
                      "avgRdr", "avgKbd", "avgRvrt", "avgMonFlt", "avgElam"],
        "task_kw":   ["avg"],
        "reg_keys":  [r"HKLM\SOFTWARE\AVG",
                      r"HKLM\SOFTWARE\WOW6432Node\AVG",
                      r"HKLM\SOFTWARE\Avg",
                      r"HKCU\SOFTWARE\AVG"],
        "paths":     [r"%ProgramFiles%\AVG",
                      r"%ProgramFiles(x86)%\AVG",
                      r"%ProgramData%\AVG",
                      r"%ProgramData%\Avg"],
        "uninstall_match": ["avg antivirus", "avg internet security", "avg "],
        "ifeo_exe":  ["AVGUI.exe", "avg_antivirus_free_setup.exe",
                      "avg_free_x64_setup.exe", "instup.exe", "AVGBrowserSetup.exe"],
    },

    "Norton AntiVirus": {
        "processes": ["NortonSecurity.exe", "NortonUI.exe", "ccSvcHst.exe",
                      "NSDUiApp.exe", "NortonInternetSecurity.exe", "nortonsecurity.exe",
                      "NABUService.exe", "nsWscSvc.exe", "uiStub.exe"],
        "services":  ["NortonSecurity", "Norton", "NAUpdate",
                      "NSDUIParentService", "nsWscSvc"],
        "drivers":   ["BHDrvx64", "ccSetx64", "eeCtrl", "EraserUtilRebootDrv",
                      "IDSvia64", "SRTSP", "SRTSPX", "SymEFASI", "SymELAM",
                      "SymEvent", "SymIRON", "SymNetS", "SymDS", "SymHsm"],
        "task_kw":   ["norton"],
        "reg_keys":  [r"HKLM\SOFTWARE\Norton",
                      r"HKLM\SOFTWARE\WOW6432Node\Norton",
                      r"HKLM\SOFTWARE\Symantec",
                      r"HKLM\SOFTWARE\WOW6432Node\Symantec",
                      r"HKCU\SOFTWARE\Norton"],
        "paths":     [r"%ProgramFiles%\Norton Security",
                      r"%ProgramFiles(x86)%\Norton Security",
                      r"%ProgramData%\Norton",
                      r"%ProgramData%\NortonInstaller",
                      r"%ProgramFiles%\NortonInstaller"],
        "uninstall_match": ["norton", "norton antivirus", "norton security", "norton 360"],
        "ifeo_exe":  ["NortonSecurity.exe", "NRnR.exe", "NortonInstaller.exe",
                      "NortonSetup.exe", "N360Downloader.exe"],
    },

    "BKAV": {
        "processes": ["Bka.exe", "BkavService.exe", "BkavSystemServer.exe",
                      "BLuPro.exe", "Bav.exe", "BkavUtil.exe", "Bkav.exe",
                      "BkavAutoUpdate.exe", "BkavProMonitor.exe", "BkavWsctrl.exe"],
        "services":  ["BkavService", "BkavServiceAutoProtect", "BkavSystemServer",
                      "BkavProService", "BkavAutoProtect"],
        "drivers":   ["BkavAutoProtect", "BkavSsdt", "BkavDrv", "BkavFsFlt",
                      "BkavProtect", "BkavMonFlt"],
        "task_kw":   ["bkav"],
        "reg_keys":  [r"HKLM\SOFTWARE\Bkav",
                      r"HKLM\SOFTWARE\WOW6432Node\Bkav",
                      r"HKCU\SOFTWARE\Bkav"],
        "paths":     [r"%ProgramFiles%\Bkav",
                      r"%ProgramFiles(x86)%\Bkav",
                      r"C:\Bkav",
                      r"%ProgramData%\Bkav"],
        "uninstall_match": ["bkav"],
        "ifeo_exe":  ["Bkav.exe", "Bka.exe", "BkavSetup.exe", "BkavPro.exe",
                      "BkavHome.exe", "BkavInstaller.exe"],
    },

    "McAfee": {
        "processes": ["mcuicnt.exe", "McUICnt.exe", "mcapexe.exe", "MfeAVSvc.exe",
                      "mfefire.exe", "mfevtps.exe", "ModuleCoreService.exe",
                      "MMSSHOST.exe", "masvc.exe", "macmnsvc.exe", "mcshield.exe",
                      "McCSPServiceHost.exe", "mcapexe.exe", "mcpltsvc.exe"],
        "services":  ["mfefire", "mfevtp", "McAPExe", "McAWFwk", "mccspsvc",
                      "modulecoreservice", "PEFService", "McMPFSvc", "McComponentHostService"],
        "drivers":   ["mfeavfk", "mfefirek", "mfehidk", "mfencbdc", "mfeelamk",
                      "mfewfpk", "mfencrk", "cfwids", "mfeclnk", "mfeplk"],
        "task_kw":   ["mcafee"],
        "reg_keys":  [r"HKLM\SOFTWARE\McAfee",
                      r"HKLM\SOFTWARE\WOW6432Node\McAfee",
                      r"HKLM\SOFTWARE\McAfee.com",
                      r"HKCU\SOFTWARE\McAfee"],
        "paths":     [r"%ProgramFiles%\McAfee",
                      r"%ProgramFiles(x86)%\McAfee",
                      r"%ProgramFiles%\Common Files\McAfee",
                      r"%ProgramFiles(x86)%\Common Files\McAfee",
                      r"%ProgramData%\McAfee"],
        "uninstall_match": ["mcafee"],
        "ifeo_exe":  ["mcuicnt.exe", "McUICnt.exe", "mcafee_setup.exe",
                      "McAfeeSetup.exe", "mccleanup.exe"],
    },
}


# ==========================================================================
#  Quyền Administrator / UAC
# ==========================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin():
    """Khởi động lại chính nó với quyền Admin."""
    try:
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            f'"{os.path.abspath(sys.argv[0])}" {params}', None, 1)
    except Exception as e:
        print("Không thể nâng quyền:", e)
    sys.exit(0)


# ==========================================================================
#  Cấu hình (config.json) - sửa tay được
# ==========================================================================
DEFAULT_CONFIG = {
    "ifeo_block_message": "Phần mềm này đã bị CHẶN cài đặt bởi Deep Remover.",
    "delete_locked_on_reboot": True,
    "run_vendor_uninstaller": True,
    "create_restore_point": True,
    "backup_registry_before_delete": True,
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CFG_PATH):
        try:
            with open(CFG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    else:
        save_config(cfg)
    return cfg


def save_config(cfg):
    try:
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ==========================================================================
#  CSDL SQLite - lịch sử thao tác (theo sở thích: 1 file + backup + import JSON)
# ==========================================================================
def backup_old_file(path):
    if os.path.exists(path):
        try:
            bak = path + ".bak_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            shutil.copy2(path, bak)
        except Exception:
            pass


def init_db():
    first = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT,
            product   TEXT,
            action    TEXT,
            component TEXT,
            target    TEXT,
            status    TEXT,
            detail    TEXT
        )""")
    conn.commit()
    # Tự import dữ liệu JSON cũ nếu có (deep_remover_history.json)
    old_json = os.path.join(BASE_DIR, "deep_remover_history.json")
    if first and os.path.exists(old_json):
        try:
            with open(old_json, "r", encoding="utf-8") as f:
                rows = json.load(f)
            for r in rows:
                conn.execute(
                    "INSERT INTO history(ts,product,action,component,target,status,detail)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (r.get("ts"), r.get("product"), r.get("action"),
                     r.get("component"), r.get("target"), r.get("status"),
                     r.get("detail")))
            conn.commit()
            backup_old_file(old_json)
        except Exception:
            pass
    return conn


DB = None


def log_db(product, action, component, target, status, detail=""):
    try:
        DB.execute(
            "INSERT INTO history(ts,product,action,component,target,status,detail)"
            " VALUES(?,?,?,?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec="seconds"),
             product, action, component, target, status, detail))
        DB.commit()
    except Exception:
        pass


# ==========================================================================
#  Tiện ích chạy lệnh hệ thống
# ==========================================================================
def run(cmd, timeout=60):
    """Chạy lệnh, trả (returncode, stdout+stderr)."""
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str),
                           capture_output=True, text=True,
                           timeout=timeout, creationflags=CREATE_NO_WINDOW)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except Exception as e:
        return -1, str(e)


def expand(path):
    return os.path.expandvars(path)


def delete_on_reboot(path):
    """Xếp lịch xóa file/thư mục khi khởi động lại (cho file đang bị khóa)."""
    try:
        res = ctypes.windll.kernel32.MoveFileExW(
            ctypes.c_wchar_p(path), None, MOVEFILE_DELAY_UNTIL_REBOOT)
        return res != 0
    except Exception:
        return False


# ==========================================================================
#  Lớp logic chính
# ==========================================================================
class Engine:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger          # hàm ghi log ra GUI

    # ----- tiến trình -----
    def list_running(self, procs):
        rc, out = run('tasklist /fo csv /nh')
        running = []
        low = out.lower()
        for p in procs:
            if p.lower() in low:
                running.append(p)
        return running

    def kill_processes(self, product, procs):
        for p in procs:
            rc, out = run(f'taskkill /F /IM "{p}" /T')
            status = "OK" if rc == 0 else "skip"
            if rc == 0:
                self.log(f"   • Kill tiến trình: {p}")
                log_db(product, "kill", "process", p, status, out.strip()[:200])

    # ----- dịch vụ -----
    def service_exists(self, name):
        rc, out = run(f'sc query "{name}"')
        return rc == 0 and "SERVICE_NAME" in out.upper() or "STATE" in out.upper()

    def stop_delete_service(self, product, name, is_driver=False):
        run(f'sc stop "{name}"')
        # Hạ khởi động về disabled (quan trọng với driver tự bảo vệ)
        run(f'sc config "{name}" start= disabled')
        rc, out = run(f'sc delete "{name}"')
        if rc == 0:
            self.log(f"   • Xóa {'driver' if is_driver else 'service'}: {name}")
            log_db(product, "delete", "driver" if is_driver else "service",
                   name, "OK")
        else:
            # Không xóa được (đang chạy / tự bảo vệ) -> đã disabled, xóa reg khi reboot
            self.log(f"   • {name}: không xóa được khi đang chạy -> đã disabled, "
                     f"sẽ gỡ sau khi khởi động lại")
            run(f'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}" /f')
            log_db(product, "disable", "driver" if is_driver else "service",
                   name, "pending_reboot", out.strip()[:200])

    # ----- scheduled tasks -----
    def delete_tasks(self, product, keywords):
        rc, out = run('schtasks /query /fo csv /nh')
        if rc != 0:
            return
        for line in out.splitlines():
            if not line.strip():
                continue
            # cột đầu là tên task (có dấu ")
            taskname = line.split('","')[0].strip('"').strip()
            low = taskname.lower()
            if any(k.lower() in low for k in keywords):
                r2, o2 = run(f'schtasks /delete /tn "{taskname}" /f')
                if r2 == 0:
                    self.log(f"   • Xóa Scheduled Task: {taskname}")
                    log_db(product, "delete", "task", taskname, "OK")

    # ----- registry -----
    def backup_regkey(self, key):
        if not self.cfg.get("backup_registry_before_delete", True):
            return
        safe = key.replace("\\", "_").replace(":", "").replace(" ", "")
        folder = os.path.join(BASE_DIR, "reg_backup")
        os.makedirs(folder, exist_ok=True)
        dst = os.path.join(folder, safe + ".reg")
        run(f'reg export "{key}" "{dst}" /y')

    def delete_regkeys(self, product, keys):
        for k in keys:
            # kiểm tra tồn tại
            rc, _ = run(f'reg query "{k}"')
            if rc != 0:
                continue
            self.backup_regkey(k)
            r2, out = run(f'reg delete "{k}" /f')
            # thử cả 2 view 32/64
            run(f'reg delete "{k}" /f /reg:64')
            run(f'reg delete "{k}" /f /reg:32')
            if r2 == 0:
                self.log(f"   • Xóa Registry: {k}")
                log_db(product, "delete", "registry", k, "OK")

    # ----- file / thư mục -----
    def delete_paths(self, product, paths):
        for raw in paths:
            path = expand(raw)
            if not os.path.exists(path):
                continue
            ok = self._force_delete(path)
            if ok:
                self.log(f"   • Xóa: {path}")
                log_db(product, "delete", "path", path, "OK")
            elif self.cfg.get("delete_locked_on_reboot", True):
                self._schedule_delete_tree(path)
                self.log(f"   • Khóa, sẽ xóa khi reboot: {path}")
                log_db(product, "delete", "path", path, "pending_reboot")

    def _force_delete(self, path):
        try:
            if os.path.isdir(path):
                # gỡ thuộc tính read-only
                run(f'attrib -r -s -h "{path}\\*.*" /s /d')
                shutil.rmtree(path, ignore_errors=True)
                return not os.path.exists(path)
            else:
                run(f'attrib -r -s -h "{path}"')
                os.remove(path)
                return not os.path.exists(path)
        except Exception:
            return False

    def _schedule_delete_tree(self, path):
        # Xếp lịch xóa toàn bộ cây file khi reboot
        for root, dirs, files in os.walk(path, topdown=False):
            for f in files:
                delete_on_reboot(os.path.join(root, f))
            for d in dirs:
                delete_on_reboot(os.path.join(root, d))
        delete_on_reboot(path)

    # ----- vendor uninstaller trong Registry Uninstall -----
    def find_uninstallers(self, matches):
        found = []
        roots = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        for root in roots:
            rc, out = run(f'reg query "{root}"')
            if rc != 0:
                continue
            for sub in out.splitlines():
                sub = sub.strip()
                if not sub.startswith("HKEY"):
                    continue
                rc2, o2 = run(f'reg query "{sub}" /v DisplayName')
                if rc2 != 0:
                    continue
                name = ""
                for ln in o2.splitlines():
                    if "DisplayName" in ln:
                        parts = ln.split("REG_SZ")
                        if len(parts) > 1:
                            name = parts[1].strip()
                if not name:
                    continue
                if any(m.lower() in name.lower() for m in matches):
                    # lấy lệnh gỡ
                    cmd = ""
                    for vn in ("QuietUninstallString", "UninstallString"):
                        rc3, o3 = run(f'reg query "{sub}" /v {vn}')
                        if rc3 == 0:
                            for ln in o3.splitlines():
                                if vn in ln:
                                    p = ln.split("REG_SZ")
                                    if len(p) > 1 and p[1].strip():
                                        cmd = p[1].strip()
                        if cmd:
                            break
                    found.append((name, cmd))
        return found

    def run_vendor_uninstaller(self, product, matches):
        if not self.cfg.get("run_vendor_uninstaller", True):
            return
        for name, cmd in self.find_uninstallers(matches):
            if not cmd:
                continue
            self.log(f"   • Chạy trình gỡ của hãng: {name}")
            log_db(product, "vendor_uninstall", "uninstaller", name, "run", cmd)
            # thêm cờ silent phổ biến nếu chưa có
            run(cmd, timeout=600)

    # ----- IFEO: chặn / cho phép -----
    def ifeo_base(self, exe):
        return (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + exe)

    def ifeo_block(self, product, exe_list):
        msg = self.cfg.get("ifeo_block_message", "Da bi chan.")
        # Debugger = mshta hiển thị messagebox rồi thoát (không mở console)
        debugger = ('C:\\Windows\\System32\\mshta.exe vbscript:Execute('
                    '"MsgBox ""%s"",48,""Deep Remover"":close")' % msg)
        for exe in exe_list:
            key = self.ifeo_base(exe)
            run(f'reg add "{key}" /v Debugger /t REG_SZ /d {chr(34)}{debugger}{chr(34)} /f')
            self.log(f"   • CHẶN cài lại: {exe}")
            log_db(product, "ifeo_block", "ifeo", exe, "OK")

    def ifeo_allow(self, product, exe_list):
        for exe in exe_list:
            key = self.ifeo_base(exe)
            rc, _ = run(f'reg query "{key}" /v Debugger')
            if rc == 0:
                run(f'reg delete "{key}" /v Debugger /f')
                self.log(f"   • CHO PHÉP cài lại: {exe}")
                log_db(product, "ifeo_allow", "ifeo", exe, "OK")

    def ifeo_status(self, exe_list):
        for exe in exe_list:
            rc, _ = run(f'reg query "{self.ifeo_base(exe)}" /v Debugger')
            if rc == 0:
                return True
        return False

    # ----- khôi phục hệ thống -----
    def create_restore_point(self, desc):
        if not self.cfg.get("create_restore_point", True):
            return
        ps = ('powershell -ExecutionPolicy Bypass -Command '
              '"Enable-ComputerRestore -Drive \'C:\\\'; '
              f'Checkpoint-Computer -Description \'{desc}\' '
              '-RestorePointType APPLICATION_INSTALL"')
        self.log("   • Đang tạo điểm khôi phục hệ thống...")
        run(ps, timeout=180)


# ==========================================================================
#  Giao diện (GUI)
# ==========================================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.geometry("1040x720")
        self.minsize(960, 640)

        self.cfg = load_config()
        self.engine = Engine(self.cfg, self.log)
        self.vars = {}          # product -> BooleanVar
        self.busy = False

        self._build_ui()
        self.log(f"Sẵn sàng. Quyền Admin: {'CÓ' if is_admin() else 'KHÔNG'}")
        if not is_admin():
            self.log("⚠ Chưa chạy quyền Admin - nhiều thao tác sẽ thất bại!")

    # -------------------------------------------------- UI
    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="DEEP REMOVER", font=("Segoe UI", 16, "bold")
                  ).pack(side="left")
        ttk.Label(top, text="  Gỡ sạch triệt để + Chặn cài lại (IFEO)",
                  font=("Segoe UI", 10)).pack(side="left")

        # Khung chọn sản phẩm
        mid = ttk.Frame(self, padding=(10, 0))
        mid.pack(fill="x")

        box = ttk.LabelFrame(mid, text=" Chọn phần mềm cần xử lý ", padding=10)
        box.pack(fill="x")

        self.tree_vars = {}
        cols = 2
        for i, name in enumerate(PRODUCTS):
            var = tk.BooleanVar(value=False)
            self.vars[name] = var
            cb = ttk.Checkbutton(box, text=name, variable=var)
            cb.grid(row=i // cols, column=i % cols, sticky="w", padx=8, pady=3)

        selrow = ttk.Frame(box)
        selrow.grid(row=(len(PRODUCTS) + 1) // cols, column=0, columnspan=cols,
                    sticky="w", pady=(6, 0))
        ttk.Button(selrow, text="Chọn tất cả",
                   command=lambda: self._set_all(True)).pack(side="left", padx=3)
        ttk.Button(selrow, text="Bỏ chọn",
                   command=lambda: self._set_all(False)).pack(side="left", padx=3)

        # Tùy chọn
        optf = ttk.LabelFrame(mid, text=" Tùy chọn ", padding=10)
        optf.pack(fill="x", pady=8)
        self.opt_vendor = tk.BooleanVar(value=self.cfg["run_vendor_uninstaller"])
        self.opt_restore = tk.BooleanVar(value=self.cfg["create_restore_point"])
        self.opt_reboot = tk.BooleanVar(value=self.cfg["delete_locked_on_reboot"])
        self.opt_ifeo_after = tk.BooleanVar(value=False)
        ttk.Checkbutton(optf, text="Chạy trình gỡ của hãng (nếu có)",
                        variable=self.opt_vendor).grid(row=0, column=0, sticky="w", padx=6)
        ttk.Checkbutton(optf, text="Tạo điểm khôi phục trước khi gỡ",
                        variable=self.opt_restore).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Checkbutton(optf, text="Xóa file bị khóa khi khởi động lại",
                        variable=self.opt_reboot).grid(row=1, column=0, sticky="w", padx=6)
        ttk.Checkbutton(optf, text="Tự CHẶN cài lại (IFEO) sau khi gỡ xong",
                        variable=self.opt_ifeo_after).grid(row=1, column=1, sticky="w", padx=6)

        # Nút hành động
        btnf = ttk.Frame(self, padding=(10, 0))
        btnf.pack(fill="x")
        ttk.Button(btnf, text="🔍  QUÉT SÂU", width=18,
                   command=lambda: self._run_thread(self.do_scan)).pack(side="left", padx=4)
        ttk.Button(btnf, text="🧹  GỠ SẠCH", width=18,
                   command=lambda: self._run_thread(self.do_remove)).pack(side="left", padx=4)
        ttk.Button(btnf, text="⛔  CHẶN CÀI LẠI", width=18,
                   command=lambda: self._run_thread(self.do_block)).pack(side="left", padx=4)
        ttk.Button(btnf, text="✅  CHO PHÉP CÀI LẠI", width=20,
                   command=lambda: self._run_thread(self.do_allow)).pack(side="left", padx=4)

        btnf2 = ttk.Frame(self, padding=(10, 4))
        btnf2.pack(fill="x")
        ttk.Button(btnf2, text="Boot vào Safe Mode", width=18,
                   command=self.safe_mode).pack(side="left", padx=4)
        ttk.Button(btnf2, text="Tắt Safe Mode", width=14,
                   command=self.safe_mode_off).pack(side="left", padx=4)
        ttk.Button(btnf2, text="Xem lịch sử", width=14,
                   command=self.show_history).pack(side="left", padx=4)
        ttk.Button(btnf2, text="Xóa log màn hình", width=16,
                   command=lambda: self.txt.delete("1.0", "end")).pack(side="left", padx=4)

        # Log
        logf = ttk.LabelFrame(self, text=" Nhật ký ", padding=6)
        logf.pack(fill="both", expand=True, padx=10, pady=8)
        self.txt = scrolledtext.ScrolledText(logf, wrap="word",
                                             font=("Consolas", 9), height=18)
        self.txt.pack(fill="both", expand=True)

        self.status = tk.StringVar(value="Sẵn sàng")
        ttk.Label(self, textvariable=self.status, relief="sunken",
                  anchor="w", padding=4).pack(fill="x", side="bottom")

    def _set_all(self, v):
        for var in self.vars.values():
            var.set(v)

    def selected_products(self):
        return [n for n, v in self.vars.items() if v.get()]

    # -------------------------------------------------- log helpers
    def log(self, msg):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.update_idletasks()

    def set_status(self, s):
        self.status.set(s)
        self.update_idletasks()

    # -------------------------------------------------- threading
    def _run_thread(self, fn):
        if self.busy:
            messagebox.showinfo(APP_NAME, "Đang xử lý, vui lòng đợi...")
            return
        self.busy = True
        t = threading.Thread(target=self._wrap, args=(fn,), daemon=True)
        t.start()

    def _wrap(self, fn):
        try:
            fn()
        except Exception as e:
            self.log(f"‼ Lỗi: {e}")
        finally:
            self.busy = False
            self.set_status("Hoàn tất")

    # -------------------------------------------------- Actions
    def do_scan(self):
        prods = self.selected_products()
        if not prods:
            self.log("Hãy chọn ít nhất 1 phần mềm để quét.")
            return
        self.log("\n========== QUÉT SÂU ==========")
        for name in prods:
            self.set_status(f"Đang quét: {name}")
            d = PRODUCTS[name]
            self.log(f"\n▶ {name}")
            run_procs = self.engine.list_running(d["processes"])
            self.log(f"   Tiến trình đang chạy: {', '.join(run_procs) or 'không'}")

            svc_found = [s for s in d["services"] if self.engine.service_exists(s)]
            self.log(f"   Dịch vụ: {', '.join(svc_found) or 'không'}")
            drv_found = [s for s in d["drivers"] if self.engine.service_exists(s)]
            self.log(f"   Driver:  {', '.join(drv_found) or 'không'}")

            paths = [expand(p) for p in d["paths"] if os.path.exists(expand(p))]
            self.log(f"   Thư mục còn lại: {len(paths)}")
            for p in paths:
                self.log(f"      - {p}")

            uns = self.engine.find_uninstallers(d["uninstall_match"])
            if uns:
                self.log(f"   Có trong Programs & Features: "
                         f"{', '.join(n for n, _ in uns)}")

            blocked = self.engine.ifeo_status(d["ifeo_exe"])
            self.log(f"   Trạng thái IFEO: {'ĐANG CHẶN' if blocked else 'bình thường'}")
        self.log("\n========== HẾT QUÉT ==========")

    def do_remove(self):
        prods = self.selected_products()
        if not prods:
            self.log("Hãy chọn phần mềm cần gỡ.")
            return
        if not is_admin():
            messagebox.showwarning(APP_NAME, "Cần chạy quyền Admin để gỡ!")
            return
        if not messagebox.askyesno(
                APP_NAME,
                "Gỡ SẠCH triệt để các phần mềm đã chọn?\n\n"
                "Thao tác xóa service/driver/registry/file.\n"
                "Nên tạo điểm khôi phục trước.\n\nTiếp tục?"):
            return

        # đồng bộ tùy chọn vào cfg
        self.cfg["run_vendor_uninstaller"] = self.opt_vendor.get()
        self.cfg["create_restore_point"] = self.opt_restore.get()
        self.cfg["delete_locked_on_reboot"] = self.opt_reboot.get()
        save_config(self.cfg)

        if self.opt_restore.get():
            self.engine.create_restore_point("Truoc khi Deep Remover go phan mem")

        self.log("\n========== BẮT ĐẦU GỠ SẠCH ==========")
        for name in prods:
            self.set_status(f"Đang gỡ: {name}")
            d = PRODUCTS[name]
            self.log(f"\n▶ {name}")

            # 1) chạy trình gỡ hãng
            self.engine.run_vendor_uninstaller(name, d["uninstall_match"])
            # 2) kill tiến trình
            self.engine.kill_processes(name, d["processes"])
            time.sleep(1)
            # 3) scheduled tasks
            self.engine.delete_tasks(name, d["task_kw"])
            # 4) services
            for s in d["services"]:
                if self.engine.service_exists(s):
                    self.engine.stop_delete_service(name, s, is_driver=False)
            # 5) drivers (tự bảo vệ)
            for s in d["drivers"]:
                if self.engine.service_exists(s):
                    self.engine.stop_delete_service(name, s, is_driver=True)
            # 6) registry
            self.engine.delete_regkeys(name, d["reg_keys"])
            # 7) file/thư mục
            self.engine.delete_paths(name, d["paths"])
            # 8) IFEO chặn nếu chọn
            if self.opt_ifeo_after.get():
                self.engine.ifeo_block(name, d["ifeo_exe"])

            self.log(f"✔ Xong: {name}")

        self.log("\n========== HOÀN TẤT ==========")
        self.log("⚠ Nếu AV có self-protection: hãy KHỞI ĐỘNG LẠI, rồi vào "
                 "Safe Mode và chạy GỠ SẠCH lần nữa để dọn phần còn khóa.")
        if messagebox.askyesno(APP_NAME, "Đã gỡ xong. Khởi động lại máy ngay để "
                               "hoàn tất việc xóa các thành phần bị khóa?"):
            run("shutdown /r /t 5")

    def do_block(self):
        prods = self.selected_products()
        if not prods:
            self.log("Chọn phần mềm cần CHẶN cài lại.")
            return
        if not is_admin():
            messagebox.showwarning(APP_NAME, "Cần quyền Admin!")
            return
        self.log("\n========== CHẶN CÀI LẠI (IFEO) ==========")
        for name in prods:
            self.log(f"\n▶ {name}")
            self.engine.ifeo_block(name, PRODUCTS[name]["ifeo_exe"])
        self.log("Đã chặn. Khi chạy file cài, Windows sẽ hiện thông báo chặn.")

    def do_allow(self):
        prods = self.selected_products()
        if not prods:
            self.log("Chọn phần mềm cần CHO PHÉP cài lại.")
            return
        if not is_admin():
            messagebox.showwarning(APP_NAME, "Cần quyền Admin!")
            return
        self.log("\n========== CHO PHÉP CÀI LẠI ==========")
        for name in prods:
            self.log(f"\n▶ {name}")
            self.engine.ifeo_allow(name, PRODUCTS[name]["ifeo_exe"])
        self.log("Đã bỏ chặn.")

    # -------------------------------------------------- Safe mode
    def safe_mode(self):
        if not is_admin():
            messagebox.showwarning(APP_NAME, "Cần quyền Admin!")
            return
        if messagebox.askyesno(APP_NAME,
                "Đặt máy khởi động vào Safe Mode (lần sau)?\n"
                "Dùng để gỡ AV tự bảo vệ. Nhớ 'Tắt Safe Mode' sau khi xong."):
            run("bcdedit /set {current} safeboot minimal")
            self.log("Đã đặt Safe Mode. Khởi động lại để vào.")
            if messagebox.askyesno(APP_NAME, "Khởi động lại ngay?"):
                run("shutdown /r /t 5")

    def safe_mode_off(self):
        if not is_admin():
            messagebox.showwarning(APP_NAME, "Cần quyền Admin!")
            return
        run("bcdedit /deletevalue {current} safeboot")
        self.log("Đã tắt Safe Mode. Lần sau khởi động bình thường.")

    # -------------------------------------------------- History
    def show_history(self):
        win = tk.Toplevel(self)
        win.title("Lịch sử thao tác")
        win.geometry("900x500")
        cols = ("ts", "product", "action", "component", "target", "status")
        tv = ttk.Treeview(win, columns=cols, show="headings")
        for c, w in zip(cols, (140, 140, 90, 80, 300, 90)):
            tv.heading(c, text=c)
            tv.column(c, width=w, anchor="w")
        tv.pack(fill="both", expand=True)
        try:
            for row in DB.execute(
                    "SELECT ts,product,action,component,target,status "
                    "FROM history ORDER BY id DESC LIMIT 500"):
                tv.insert("", "end", values=row)
        except Exception as e:
            tv.insert("", "end", values=("", "", "", "", str(e), ""))


# ==========================================================================
def main():
    global DB
    if os.name != "nt":
        print("Tool này chỉ chạy trên Windows.")
        # vẫn cho mở GUI để xem, nhưng cảnh báo
    if os.name == "nt" and not is_admin():
        relaunch_as_admin()
        return
    DB = init_db()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
