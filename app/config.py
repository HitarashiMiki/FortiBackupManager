from __future__ import annotations
import json
import base64
from pathlib import Path
from dataclasses import dataclass, asdict

from .storage import StorageConfig

SETTINGS_FILE = Path.home() / ".fortibackup-web" / "settings.json"


@dataclass
class AppSettings:
    protocol: str = "sftp"
    host: str = ""
    port: int = 22
    username: str = ""
    password_obf: str = ""
    base_path: str = "/fortibackup"

    def to_storage_config(self) -> StorageConfig:
        return StorageConfig(
            protocol=self.protocol,
            host=self.host,
            port=self.port,
            username=self.username,
            password=_deobf(self.password_obf),
            base_path=self.base_path,
        )


def _obf(s: str) -> str:
    return base64.b64encode(s.encode()).decode() if s else ""


def _deobf(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode() if s else ""
    except Exception:
        return ""


def load_settings() -> AppSettings:
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return AppSettings(**data)
    except Exception:
        return AppSettings()


def save_settings(settings: AppSettings):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")