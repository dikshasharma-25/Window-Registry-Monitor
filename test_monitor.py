from monitor import compare_registry, save_changes

# Simulated original registry data
old_data = {
    "HKCU\\TEST": {
        "status": "success",
        "values": {
            "TestApp": {
                "value": "old.exe",
                "type": 1
            }
        }
    }
}

# Simulated current registry data
new_data = {
    "HKCU\\TEST": {
        "status": "success",
        "values": {
            "TestApp": {
                "value": "new.exe",
                "type": 1
            },
            "UnknownApp": {
                "value": "unknown.exe",
                "type": 1
            }
        }
    }
}

# Detect changes
changes = compare_registry(old_data, new_data)

print("\nDETECTION TEST RESULTS")
print("=" * 40)

for change in changes:
    print("Change Type:", change["type"])
    print("Registry:", change["registry_path"])
    print("Value Name:", change["value_name"])
    print("Old Value:", change["old_value"])
    print("New Value:", change["new_value"])
    print("-" * 40)

# Save detected changes
if changes:
    save_changes(changes)
    print("Changes successfully saved!")

else:
    print("No changes detected.")