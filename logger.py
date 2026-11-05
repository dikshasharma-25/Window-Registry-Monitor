import logging
import os

# Create logs folder if it does not exist
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    filename="logs/registry_changes.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    force=True
)


def log_change(change):

    change_type = change["type"]
    entry_name = change["name"]

    message = (
        f"Change Type: {change_type} | "
        f"Registry Entry: {entry_name}"
    )

    if "old_value" in change:
        message += f" | Old Value: {change['old_value']}"

    if "new_value" in change:
        message += f" | New Value: {change['new_value']}"

    logging.info(message)

    print("Change saved in log file.")


# Example testing

if __name__ == "__main__":

    test_change = {
        "type": "ADDED",
        "name": "UnknownApp",
        "new_value": "unknown.exe"
    }

    log_change(test_change)