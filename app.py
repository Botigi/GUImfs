from __future__ import annotations

import logging
import os
from urllib.parse import unquote
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from msf_bridge import MsfBridge

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DOWNLOAD_DIR = BASE_DIR / "downloads"
UPLOAD_DIR.mkdir(exist_ok=True)
DOWNLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH_MB", "50")) * 1024 * 1024

logger = logging.getLogger("session")
logger.setLevel(logging.INFO)
if not logger.handlers:
    file_handler = logging.FileHandler(BASE_DIR / "session.log")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(file_handler)

msf = MsfBridge()


@app.before_request
def try_connect() -> None:
    if msf.client is not None:
        return
    try:
        msf.connect(
            os.getenv("MSFRPC_HOST", "127.0.0.1"),
            int(os.getenv("MSFRPC_PORT", "55553")),
            os.getenv("MSFRPC_USER", "msf"),
            os.getenv("MSFRPC_PASSWORD", "password"),
            os.getenv("MSFRPC_SSL", "false").lower() == "true",
        )
        logger.info("Connected to MSFRPC")
    except Exception as exc:  # noqa: BLE001
        logger.warning("MSFRPC unavailable: %s", exc)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _ok(result: Any, status: str = "success"):
    return jsonify({"result": result, "timestamp": _ts(), "status": status})


def _err(message: str):
    return jsonify({"result": message, "timestamp": _ts(), "status": "error"}), 400


def _invalid_remote_path(path: str) -> bool:
    normalized = unquote(path).replace("\\", "/")
    return not path or "\x00" in normalized or ".." in normalized


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def api_status():
    status = msf.get_session_status()
    payload = {
        **status,
        "arrow_active": bool(status.get("compromised")),
        "timestamp": _ts(),
    }
    return jsonify(payload)


@app.get("/api/sysinfo")
def api_sysinfo():
    try:
        output = msf.run_sysinfo()
        logger.info("sysinfo")
        return jsonify({"sysinfo_output": output, "timestamp": _ts()})
    except Exception as exc:  # noqa: BLE001
        logger.error("sysinfo failed: %s", exc)
        return _err("sysinfo failed")


@app.get("/api/ps")
def api_ps():
    try:
        processes = msf.run_ps()
        logger.info("ps")
        return jsonify({"processes": processes, "timestamp": _ts()})
    except Exception as exc:  # noqa: BLE001
        logger.error("ps failed: %s", exc)
        return _err("ps failed")


@app.get("/api/screenshot")
def api_screenshot():
    try:
        image = msf.run_screenshot()
        logger.info("screenshot")
        return jsonify({"image_base64": image, "timestamp": _ts()})
    except Exception as exc:  # noqa: BLE001
        logger.error("screenshot failed: %s", exc)
        return _err("screenshot failed")


@app.post("/api/file/upload")
def api_file_upload():
    file = request.files.get("file")
    remote_path = request.form.get("remote_path", "")
    if not file or not remote_path:
        return _err("file and remote_path are required")
    if _invalid_remote_path(remote_path):
        return _err("invalid remote_path")
    safe_name = secure_filename(file.filename or "")
    if not safe_name:
        return _err("invalid filename")
    local_path = (UPLOAD_DIR / safe_name).resolve()
    upload_root = UPLOAD_DIR.resolve()
    if not local_path.is_relative_to(upload_root):
        return _err("invalid upload path")
    file.save(local_path)
    try:
        success = msf.run_upload(str(local_path), remote_path)
        logger.info("upload %s -> %s", local_path, remote_path)
        return jsonify({"success": bool(success), "timestamp": _ts()})
    except Exception as exc:  # noqa: BLE001
        logger.error("upload failed: %s", exc)
        return _err("upload failed")


@app.post("/api/file/download")
def api_file_download():
    data = request.get_json(silent=True) or {}
    remote_path = data.get("remote_path", "")
    filename = secure_filename(os.path.basename(remote_path)) or "downloaded.bin"
    local_path = (DOWNLOAD_DIR / filename).resolve()
    download_root = DOWNLOAD_DIR.resolve()
    if not remote_path:
        return _err("remote_path is required")
    if _invalid_remote_path(remote_path):
        return _err("invalid remote_path")
    if not local_path.is_relative_to(download_root):
        return _err("invalid download path")
    try:
        success = msf.run_download(remote_path, str(local_path))
        logger.info("download %s -> %s", remote_path, local_path)
        return jsonify({"success": bool(success), "timestamp": _ts()})
    except Exception as exc:  # noqa: BLE001
        logger.error("download failed: %s", exc)
        return _err("download failed")


@app.post("/api/cmd/<command>")
def api_command(command: str):
    data = request.get_json(silent=True) or {}
    try:
        handlers = {
            "getuid": msf.run_getuid,
            "getpid": lambda: str(msf.get_session_status().get("pid", "N/A")),
            "getsystem": msf.run_getsystem,
            "hashdump": msf.run_hashdump,
            "pwd": msf.run_pwd,
            "ipconfig": msf.run_ipconfig,
            "arp": msf.run_arp,
            "sysinfo": msf.run_sysinfo,
            "ps": msf.run_ps,
            "keyscan_start": lambda: msf.run_keyscan("start"),
            "keyscan_stop": lambda: msf.run_keyscan("stop"),
            "keyscan_dump": lambda: msf.run_keyscan("dump"),
            "verify_uid": msf.run_getuid,
            "ls": lambda: msf.run_ls(data.get("path", ".")),
            "portfwd": lambda: f"Portfwd requested: {data}",
            "persistence": lambda: f"Persistence requested: {data}",
            "reg_add": lambda: f"Reg add requested: {data}",
            "shell": lambda: "Shell endpoint intentionally restricted in UI mode",
            "webcam_snap": lambda: "Webcam snap not available in this environment",
        }
        if command not in handlers:
            return _err(f"Unsupported command: {command}")
        result = handlers[command]()
        logger.info("%s -> %s", command, str(result)[:200])
        return _ok(result)
    except KeyError as exc:
        logger.error("Missing field for %s: %s", command, exc)
        return _err("missing required field")
    except Exception as exc:  # noqa: BLE001
        logger.error("Command %s failed: %s", command, exc)
        return _err("command failed")


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
