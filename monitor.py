import json
import time
from datetime import datetime
from pathlib import Path

from registry_scanner import scan_all_registry
from detector import detect_suspicious_changes, save_alerts


# Project settings
BASELINE_FILE = Path("data/baseline.json")
LOG_FILE = Path("data/registry_logs.jsonl")

MONITOR_INTERVAL = 10


def load_baseline():

    if not BASELINE_FILE.exists():
        print("ERROR: Baseline file not found!")
        print("Please run: python baseline.py")
        return None

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    return baseline["registry_data"]


def compare_registry(old_data, new_data):

    changes = []

    for registry_path in set(old_data) | set(new_data):

        old_key = old_data.get(registry_path, {})
        new_key = new_data.get(registry_path, {})

        # Compare only successfully scanned keys.
        # Avoid false deletions when access is denied or a key is missing.
        if (old_key.get("status") != "success"
                or new_key.get("status") != "success"):
            continue

        old_values = old_key.get("values", {})
        new_values = new_key.get("values", {})

        old_names = set(old_values)
        new_names = set(new_values)

        # Detect added values
        for name in new_names - old_names:

            changes.append({
                "type": "ADDED",
                "registry_path": registry_path,
                "value_name": name,
                "old_value": None,
                "new_value": new_values[name]
            })

        # Detect deleted values
        for name in old_names - new_names:

            changes.append({
                "type": "DELETED",
                "registry_path": registry_path,
                "value_name": name,
                "old_value": old_values[name],
                "new_value": None
            })

        # Detect modified values
        for name in old_names & new_names:

            if old_values[name] != new_values[name]:

                changes.append({
                    "type": "MODIFIED",
                    "registry_path": registry_path,
                    "value_name": name,
                    "old_value": old_values[name],
                    "new_value": new_values[name]
                })

    return changes


def save_changes(changes):

    LOG_FILE.parent.mkdir(exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as file:

        for change in changes:

            record = {
                "timestamp": datetime.now().isoformat(),
                **change
            }

            file.write(json.dumps(record) + "\n")


def start_monitoring():

    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    print("\n" + "=" * 55)
    print(" WINDOWS REGISTRY CHANGE MONITOR")
    print("=" * 55)

    previous_data = load_baseline()

    if previous_data is None:
        return

    print("\nBaseline loaded successfully.")
    print("Monitoring interval:", MONITOR_INTERVAL, "seconds")
    print("Press CTRL + C to stop monitoring.")

    try:

        while True:

            time.sleep(MONITOR_INTERVAL)

            current_data = scan_all_registry()

            # Run malware detection
            alerts = detect_suspicious_changes(current_data)

            if alerts:

                print("\nSUSPICIOUS REGISTRY ACTIVITY DETECTED!")

                for alert in alerts:

                    print("\nSeverity:", alert["severity"])
                    print("Category:", alert["category"])
                    print("Message:", alert["message"])

                save_alerts(alerts)

                print("\nSecurity alerts saved successfully.")

            changes = compare_registry(
                previous_data,
                current_data
            )

            print("\nMonitoring Time:", datetime.now())

            if changes:

                print("\nALERT! REGISTRY CHANGES DETECTED")

                for change in changes:

                    print("\nChange Type:", change["type"])
                    print("Registry:", change["registry_path"])
                    print("Value Name:", change["value_name"])
                    print("Old Value:", change["old_value"])
                    print("New Value:", change["new_value"])

                save_changes(changes)

                print("\nChanges saved to:", LOG_FILE)

            else:

                print("No registry changes detected.")

            # Update comparison state for the next polling cycle.
            previous_data = current_data

    except KeyboardInterrupt:

        print("\nMonitoring stopped by user.")
        print("Registry monitoring session ended.")


if __name__ == "__main__":
    start_monitoring()