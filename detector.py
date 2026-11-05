import json
from datetime import datetime
from pathlib import Path

from registry_scanner import scan_all_registry

# ALERT_FILE = Path("data/alerts.jsonl")
ALERT_FILE = (Path(__file__).resolve().parent/"data"/"alerts.jsonl")

def add_alert(alerts, severity, category, message,
              registry_path, value_name, value):

    alerts.append({
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "category": category,
        "message": message,
        "registry_path": registry_path,
        "value_name": value_name,
        "value": value
    })


def detect_suspicious_changes(registry_data):

    alerts = []

    for registry_path, key_data in registry_data.items():

        if key_data.get("status") != "success":
            continue

        values = key_data.get("values", {})

        # Check autorun registry entries
        if registry_path.lower().endswith(
            ("\\run", "\\runonce")
        ):

            for name, details in values.items():

                command = str(
                    details.get("value", "")
                ).lower()

                suspicious_locations = [
                    "\\temp\\",
                    "\\downloads\\"
                ]

                suspicious_commands = [
                    "powershell -enc",
                    "powershell -encodedcommand",
                    "wscript.exe",
                    "cscript.exe",
                    "mshta.exe",
                    "rundll32.exe",
                    "regsvr32.exe"
                ]

                if any(
                    location in command
                    for location in suspicious_locations
                ):

                    add_alert(
                        alerts,
                        "HIGH",
                        "Suspicious Autorun",
                        "Startup entry launches from a temporary or download location.",
                        registry_path,
                        name,
                        details["value"]
                    )

                elif any(
                    keyword in command
                    for keyword in suspicious_commands
                ):

                    add_alert(
                        alerts,
                        "MEDIUM",
                        "Suspicious Autorun",
                        "Startup entry uses a script or system utility that requires investigation.",
                        registry_path,
                        name,
                        details["value"]
                    )

        # Check Windows Defender policies
        if "windows defender" in registry_path.lower():

            defender_flags = [
                "DisableAntiSpyware",
                "DisableRealtimeMonitoring",
                "DisableBehaviorMonitoring",
                "DisableIOAVProtection",
                "DisableOnAccessProtection"
            ]

            for name, details in values.items():

                if name.lower() in [
                    flag.lower() for flag in defender_flags
                ]:

                    if str(details["value"]).strip() == "1":

                        add_alert(
                            alerts,
                            "HIGH",
                            "Defender Policy",
                            "A Windows Defender disabling policy is enabled.",
                            registry_path,
                            name,
                            details["value"]
                        )

        # Check Windows Firewall policies
        if "windowsfirewall" in registry_path.lower():

            for name, details in values.items():

                if (
                    name.lower() == "enablefirewall"
                    and str(details["value"]).strip() == "0"
                ):

                    add_alert(
                        alerts,
                        "HIGH",
                        "Firewall Policy",
                        "Windows Firewall appears disabled by policy.",
                        registry_path,
                        name,
                        details["value"]
                    )

        # Check User Account Control
        if "policies\\system" in registry_path.lower():

            for name, details in values.items():

                if (
                    name.lower() == "enablelua"
                    and str(details["value"]).strip() == "0"
                ):

                    add_alert(
                        alerts,
                        "HIGH",
                        "UAC Configuration",
                        "User Account Control appears disabled.",
                        registry_path,
                        name,
                        details["value"]
                    )

        # Check Windows login and shell configuration
        if "winlogon" in registry_path.lower():

            for name, details in values.items():

                value = str(details["value"]).strip().lower()

                if name.lower() == "shell":

                    if value != "explorer.exe":

                        add_alert(
                            alerts,
                            "HIGH",
                            "Shell Replacement",
                            "Windows shell value differs from the normal explorer.exe setting.",
                            registry_path,
                            name,
                            details["value"]
                        )

                if name.lower() == "userinit":

                    if "userinit.exe" not in value:

                        add_alert(
                            alerts,
                            "HIGH",
                            "Login Configuration",
                            "Windows Userinit value differs from the expected configuration.",
                            registry_path,
                            name,
                            details["value"]
                        )

    return alerts


def save_alerts(alerts):

    ALERT_FILE.parent.mkdir(exist_ok=True)

    # Create the file even if there are no alerts
    ALERT_FILE.touch(exist_ok=True)

    with open(ALERT_FILE, "a", encoding="utf-8") as file:

        for alert in alerts:
            file.write(json.dumps(alert) + "\n")


def run_detection():

    print("\n" + "=" * 55)
    print(" WINDOWS REGISTRY MALWARE DETECTION SYSTEM")
    print("=" * 55)

    print("\nScanning registry for suspicious patterns...")

    registry_data = scan_all_registry()

    alerts = detect_suspicious_changes(registry_data)

    save_alerts(alerts)

    print("\n" + "=" * 55)
    print("MALWARE DETECTION RESULTS")
    print("=" * 55)

    if alerts:

        for alert in alerts:

            print("\nSeverity:", alert["severity"])
            print("Category:", alert["category"])
            print("Message:", alert["message"])
            print("Registry:", alert["registry_path"])
            print("Value:", alert["value_name"])
            print("Detected Value:", alert["value"])

    else:

        print("\nNo suspicious registry patterns detected.")

    print("\nTotal alerts:", len(alerts))
    print("Alert report:", ALERT_FILE)

    print("\nDetection completed.")


if __name__ == "__main__":
    run_detection()