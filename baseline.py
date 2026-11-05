import json
import hashlib
from datetime import datetime
from pathlib import Path

from registry_scanner import scan_all_registry

# Project directories
DATA_DIR = Path("data")
BASELINE_FILE = DATA_DIR / "baseline.json"


def calculate_hash(data):
    """Generate SHA-256 checksum of registry data."""

    content = json.dumps(
        data,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def create_baseline():

    print("\nCreating Registry Baseline...")

    # Create data folder if it does not exist
    DATA_DIR.mkdir(exist_ok=True)

    # Scan registry
    registry_data = scan_all_registry()

    # Generate checksum
    checksum = calculate_hash(registry_data)

    # Prepare baseline information
    baseline = {
        "created_at": datetime.now().isoformat(),
        "checksum": checksum,
        "registry_data": registry_data
    }

    # Save baseline as JSON
    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(
            baseline,
            file,
            indent=4,
            default=str
        )

    print("\n" + "=" * 50)
    print("REGISTRY BASELINE CREATED SUCCESSFULLY")
    print("=" * 50)

    print("File:", BASELINE_FILE)
    print("SHA-256:", checksum)


if __name__ == "__main__":
    create_baseline()