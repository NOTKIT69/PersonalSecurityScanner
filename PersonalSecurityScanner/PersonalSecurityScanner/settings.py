"""
settings.py
-----------
Handles loading, saving, and resetting application settings that persist
between runs in settings.json.
"""

import json
import os

SETTINGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")

DEFAULT_SETTINGS = {
    "theme": "Dark",
    "animation_speed": "Normal",       # Slow / Normal / Fast
    "auto_save_reports": True,
    "export_folder": os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"),
    "window_size": "1200x760",
}


class Settings:
    """Small wrapper around a JSON-backed settings dictionary."""

    def __init__(self, path: str = SETTINGS_PATH):
        self.path = path
        self.data = DEFAULT_SETTINGS.copy()
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Merge with defaults so new keys added in future versions
                # always exist, even if the file on disk is from an older version.
                merged = DEFAULT_SETTINGS.copy()
                merged.update(loaded)
                self.data = merged
            except (json.JSONDecodeError, OSError):
                self.data = DEFAULT_SETTINGS.copy()
        else:
            self.save()
        return self.data

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def reset(self):
        self.data = DEFAULT_SETTINGS.copy()
        self.save()
        return self.data
