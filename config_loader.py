import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

DEFAULT_CONFIG = {
    "ssh": {
        "host": "192.168.1.100",
        "username": "ops",
        "port": 22
    },
    "gvm": {
        "username": "admin",
        "socket_path": "/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock",
        "local_tunnel_port": 9390
    },
    "paths": {
        "report_download_dir": "./reports",
        "false_positives_file": "./false_positives.json"
    },
    "network": {
        "default_subnet_mask": "/24"
    },
    "formats": {
        "excel_csv": "c1645568-627a-11e3-a660-406186ea4fc5",
        "pdf": "c402cc3e-b531-11e1-9163-406186ea4fc5",
        "html": "6c248850-1f62-11e1-b082-406186ea4fc5",
        "xml": "a994b278-1f62-11e1-96ac-406186ea4fc5",
        "txt": "a3810a62-1f62-11e1-9219-406186ea4fc5"
    }
}

def load_config(path=CONFIG_PATH):
    if not os.path.exists(path):
        return DEFAULT_CONFIG
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            for key, val in cfg.items():
                if isinstance(val, dict) and key in merged:
                    merged[key].update(val)
                else:
                    merged[key] = val
            return merged
    except Exception as e:
        print(f"[Config Error] Failed to load config from {path}: {e}")
        return DEFAULT_CONFIG

def get_config():
    return load_config()
