"""
history.py
----------
Persists a lightweight index of past scans (for the History page) plus a
pointer to the full saved report file, backed by a JSON file on disk.

The full raw scan result for each entry is stored alongside the index so a
past scan can be reopened in the Result dashboard without re-scanning.
"""

import json
import os
import uuid


class HistoryManager:
    def __init__(self, folder: str):
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
        self.index_path = os.path.join(self.folder, "history.json")
        self.data_dir = os.path.join(self.folder, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self._entries = self._load_index()

    def _load_index(self):
        if os.path.exists(self.index_path):
            try:
                with open(self.index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save_index(self):
        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2)

    def add(self, result: dict) -> dict:
        """Save a full scan result and add a lightweight entry to the index."""
        entry_id = uuid.uuid4().hex[:12]
        data_path = os.path.join(self.data_dir, f"{entry_id}.json")
        try:
            with open(data_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        except OSError:
            data_path = None

        entry = {
            "id": entry_id,
            "url": result.get("url", ""),
            "date": result.get("date", ""),
            "time": result.get("time", ""),
            "risk_score": result.get("risk_score", 0),
            "data_path": data_path,
        }
        self._entries.append(entry)
        self._save_index()
        return entry

    def all(self):
        return list(self._entries)

    def load_full(self, entry_id: str):
        """Return the full stored scan result dict for an entry, or None."""
        for entry in self._entries:
            if entry["id"] == entry_id:
                path = entry.get("data_path")
                if path and os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            return json.load(f)
                    except (json.JSONDecodeError, OSError):
                        return None
        return None

    def delete(self, entry_id: str):
        entry = next((e for e in self._entries if e["id"] == entry_id), None)
        if entry:
            path = entry.get("data_path")
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
            self._entries = [e for e in self._entries if e["id"] != entry_id]
            self._save_index()
