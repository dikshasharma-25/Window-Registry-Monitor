from detector import detect_suspicious_changes, save_alerts

# Simulated registry data for testing

test_data = {
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run": {
        "status": "success",
        "values": {
            "TestEntry": {
                "value": r"C:\Users\Test\Downloads\test.exe",
                "type": 1
            }
        }
    }
}

# Run security detection

alerts = detect_suspicious_changes(test_data)

print("\nSECURITY ALERT DETECTION TEST")
print("=" * 40)

if alerts:
    for alert in alerts:
        print("Severity:", alert["severity"])
        print("Category:", alert["category"])
        print("Message:", alert["message"])
        print("Registry:", alert["registry_path"])

    save_alerts(alerts)

    print("\nAlerts Saved Successfully!")
    

else:
    print("No suspicious activity detected.")

print("\nTotal Security Alerts:", len(alerts))