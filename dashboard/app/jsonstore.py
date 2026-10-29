"""Small JSON file persisted atomically in the data volume."""
from __future__ import annotations

import copy
import json
import os
import tempfile
import threading

from .config import settings


class JsonStore:
    def __init__(self, name: str, defaults: dict) -> None:
        self.path = settings.data_dir / name
        self._lock = threading.Lock()
        self.data = copy.deepcopy(defaults)
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            for k, v in loaded.items():
                if isinstance(self.data.get(k), dict) and isinstance(v, dict):
                    self.data[k].update(v)
                else:
                    self.data[k] = v
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.stem}-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self.data, fh, ensure_ascii=False)
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self.data)
