import json
import os
from datetime import datetime
import pandas as pd

FP_FILE = os.path.join(os.path.dirname(__file__), "false_positives.json")

def load_fp_tags(filepath=FP_FILE):
    """Loads all false positive tags from JSON."""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("tags", [])
    except Exception as e:
        print(f"[FP Manager Error] Failed to load FP file: {e}")
        return []

def save_fp_tags(tags, filepath=FP_FILE):
    """Saves false positive tags to JSON."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"tags": tags}, f, indent=2)
        return True
    except Exception as e:
        print(f"[FP Manager Error] Failed to save FP file: {e}")
        return False

def add_fp_tag(hostname: str, nvt_name: str, reason: str = "", tagged_by: str = "admin", filepath=FP_FILE):
    """Adds a new false positive tag."""
    tags = load_fp_tags(filepath)
    # Check if already tagged
    for tag in tags:
        if tag.get("hostname") == hostname and tag.get("nvt_name") == nvt_name:
            tag["reason"] = reason
            tag["tagged_at"] = datetime.now().isoformat()
            tag["tagged_by"] = tagged_by
            return save_fp_tags(tags, filepath)
    
    # New tag
    tags.append({
        "hostname": hostname,
        "nvt_name": nvt_name,
        "reason": reason,
        "tagged_by": tagged_by,
        "tagged_at": datetime.now().isoformat()
    })
    return save_fp_tags(tags, filepath)

def remove_fp_tag(hostname: str, nvt_name: str, filepath=FP_FILE):
    """Removes an existing false positive tag."""
    tags = load_fp_tags(filepath)
    updated_tags = [t for t in tags if not (t.get("hostname") == hostname and t.get("nvt_name") == nvt_name)]
    if len(updated_tags) != len(tags):
        return save_fp_tags(updated_tags, filepath)
    return False

def filter_false_positives(df: pd.DataFrame, filepath=FP_FILE) -> pd.DataFrame:
    """
    Filters out false positives from a report DataFrame.
    Expects DataFrame to have 'Hostname' and 'NVT Name' (or 'NVT') columns.
    """
    if df.empty:
        return df
    
    tags = load_fp_tags(filepath)
    if not tags:
        return df

    # Build set of (hostname, nvt_name) tuples for fast O(1) lookup
    fp_set = {(t["hostname"].strip().lower(), t["nvt_name"].strip().lower()) for t in tags}

    # Find matching columns
    host_col = 'Hostname' if 'Hostname' in df.columns else ('Host' if 'Host' in df.columns else None)
    nvt_col = 'NVT Name' if 'NVT Name' in df.columns else ('NVT' if 'NVT' in df.columns else None)

    if not host_col or not nvt_col:
        return df

    def is_fp(row):
        h = str(row[host_col]).strip().lower()
        n = str(row[nvt_col]).strip().lower()
        return (h, n) in fp_set

    # Keep rows that are NOT false positives
    mask = ~df.apply(is_fp, axis=1)
    return df[mask].copy()

def get_fp_dataframe(filepath=FP_FILE) -> pd.DataFrame:
    """Returns all FP tags as a pandas DataFrame for UI rendering."""
    tags = load_fp_tags(filepath)
    if not tags:
        return pd.DataFrame(columns=["Hostname", "NVT Name", "Reason", "Tagged By", "Tagged At"])
    
    df = pd.DataFrame(tags)
    df.rename(columns={
        "hostname": "Hostname",
        "nvt_name": "NVT Name",
        "reason": "Reason",
        "tagged_by": "Tagged By",
        "tagged_at": "Tagged At"
    }, inplace=True)
    return df
