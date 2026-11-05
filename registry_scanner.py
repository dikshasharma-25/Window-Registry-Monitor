import winreg
from datetime import datetime

# Registry locations to monitor
SENSITIVE_KEYS = [
    {
        "hive": winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run"
    },
    {
        "hive": winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run"
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"SOFTWARE\Policies\Microsoft\Windows Defender"
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    },
    {
        "hive": winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path": r"SOFTWARE\RegistryMonitorTest"
    }
]


def scan_registry_key(hive, hive_name, path):

    results = {}

    try:
        key = winreg.OpenKey(
            hive,
            path,
            0,
            winreg.KEY_READ
        )

        try:
            index = 0

            while True:
                try:
                    name, value, value_type = winreg.EnumValue(
                        key, index
                    )

                    if isinstance(value, bytes):
                        value = value.hex()

                    results[name] = {
                        "value": value,
                        "type": value_type
                    }

                    index += 1

                except OSError:
                    break

        finally:
            winreg.CloseKey(key)

        return {
            "status": "success",
            "values": results
        }

    except FileNotFoundError:
        return {
            "status": "not_found",
            "values": {}
        }

    except PermissionError:
        return {
            "status": "access_denied",
            "values": {}
        }

    except OSError as error:
        return {
            "status": "error",
            "values": {},
            "message": str(error)
        }


def scan_all_registry():

    print("\n" + "=" * 60)
    print(" WINDOWS REGISTRY CHANGE MONITORING SYSTEM")
    print("=" * 60)

    print("Scan Time:", datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    ))

    print("\nStarting Registry Scan...\n")

    all_results = {}

    for item in SENSITIVE_KEYS:

        hive_name = item["hive_name"]
        path = item["path"]

        print("-" * 60)
        print("Registry:", hive_name + "\\" + path)

        result = scan_registry_key(
            item["hive"],
            hive_name,
            path
        )

        all_results[hive_name + "\\" + path] = result

        if result["status"] == "success":

            print("Status: Scanned successfully")

            if result["values"]:
                for name, details in result["values"].items():
                    print("Name:", name)
                    print("Value:", details["value"])
                    print()

            else:
                print("No values found in this key.")

        elif result["status"] == "not_found":
            print("Status: Key does not exist.")

        elif result["status"] == "access_denied":
            print("Status: Access denied.")

        else:
            print("Status:", result["status"])
            print(result.get("message", ""))

    print("\n" + "=" * 60)
    print("REGISTRY SCAN COMPLETED")
    print("=" * 60)

    return all_results


if __name__ == "__main__":
    scan_all_registry()