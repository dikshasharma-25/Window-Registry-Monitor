from tkinter import Tk, messagebox

def send_alert(change):

    title = "Registry Change Detected"

    message = (
        f"Type: {change['type']}\n"
        f"Registry Entry: {change['name']}"
    )

    try:
        root = Tk()
        root.withdraw()

        messagebox.showwarning(title, message)

        root.destroy()

    except Exception as error:
        print("Alert Error:", error)


# Example testing

if __name__ == "__main__":

    test_change = {
        "type": "ADDED",
        "name": "UnknownApp"
    }

    send_alert(test_change)
    