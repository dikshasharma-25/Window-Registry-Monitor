import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os
import json
from pathlib import Path

# Project directory
BASE_DIR = Path(__file__).resolve().parent

# Data files
DATA_DIR = BASE_DIR / "data"
LOG_FILE = BASE_DIR / "logs" / "registry_changes.log"

REGISTRY_LOGS = DATA_DIR / "registry_logs.jsonl"
ALERTS_FILE = DATA_DIR / "alerts.jsonl"


class RegistryDashboard:

    def __init__(self, root):

        self.root = root
        self.root.title("Windows Registry Monitoring System")
        self.root.geometry("1150x700")
        self.root.configure(bg="#101827")

        self.monitor_process = None
        self.refresh_job = None

        self.total_changes = 0
        self.total_alerts = 0

        self.create_dashboard()

        self.refresh_dashboard()
        self.schedule_refresh()

    # Dashboard design
    def create_dashboard(self):

        title = tk.Label(
            self.root,
            text="WINDOWS REGISTRY MONITOR",
            font=("Arial", 22, "bold"),
            bg="#101827",
            fg="white"
        )
        title.pack(pady=15)

        subtitle = tk.Label(
            self.root,
            text="Registry Change Detection and Security Monitoring",
            font=("Arial", 11),
            bg="#101827",
            fg="#9CA3AF"
        )
        subtitle.pack()

        # Monitoring status
        self.status_label = tk.Label(
            self.root,
            text="● Monitoring Stopped",
            font=("Arial", 13, "bold"),
            bg="#101827",
            fg="#F87171"
        )
        self.status_label.pack(pady=12)

        # Statistics
        stats_frame = tk.Frame(
            self.root,
            bg="#101827"
        )
        stats_frame.pack(pady=12)

        self.change_label = self.create_card(
            stats_frame, "TOTAL CHANGES", "0", 0
        )

        self.alert_label = self.create_card(
            stats_frame, "SECURITY ALERTS", "0", 1
        )

        self.added_label = self.create_card(
            stats_frame, "ADDED", "0", 2
        )

        self.modified_label = self.create_card(
            stats_frame, "MODIFIED", "0", 3
        )

        self.deleted_label = self.create_card(
            stats_frame, "DELETED", "0", 4
        )

        # Buttons
        button_frame = tk.Frame(
            self.root,
            bg="#101827"
        )
        button_frame.pack(pady=15)

        tk.Button(
            button_frame,
            text="START MONITORING",
            command=self.start_monitoring,
            bg="#16A34A",
            fg="white",
            font=("Arial", 10, "bold"),
            width=19
        ).grid(row=0, column=0, padx=8)

        tk.Button(
            button_frame,
            text="STOP MONITORING",
            command=self.stop_monitoring,
            bg="#DC2626",
            fg="white",
            font=("Arial", 10, "bold"),
            width=19
        ).grid(row=0, column=1, padx=8)

        tk.Button(
            button_frame,
            text="VIEW LOGS",
            command=self.view_logs,
            bg="#2563EB",
            fg="white",
            font=("Arial", 10, "bold"),
            width=19
        ).grid(row=0, column=2, padx=8)

        tk.Button(
            button_frame,
            text="REFRESH DATA",
            command=self.manual_refresh,
            bg="#475569",
            fg="white",
            font=("Arial", 10, "bold"),
            width=19
        ).grid(row=0, column=3, padx=8)

        # Activity heading
        tk.Label(
            self.root,
            text="REGISTRY ACTIVITY",
            font=("Arial", 15, "bold"),
            bg="#101827",
            fg="white"
        ).pack(pady=10)

        # Activity table
        table_frame = tk.Frame(
            self.root,
            bg="#101827"
        )
        table_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=10
        )

        columns = (
            "Time",
            "Change Type",
            "Registry Path",
            "Value Name",
            "Details"
        )

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#1E293B",
            foreground="white",
            fieldbackground="#1E293B",
            rowheight=28
        )

        style.configure(
            "Treeview.Heading",
            background="#334155",
            foreground="white",
            font=("Arial", 10, "bold")
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=7
        )

        widths = {
            "Time": 145,
            "Change Type": 105,
            "Registry Path": 270,
            "Value Name": 145,
            "Details": 350
        }

        for column in columns:
            self.table.heading(
                column,
                text=column
            )
            self.table.column(
                column,
                width=widths[column],
                minwidth=80
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        # Security Alerts heading
        tk.Label(
            self.root,
            text="SECURITY ALERTS",
            font=("Arial", 15, "bold"),
            bg="#101827",
            fg="white"
        ).pack(pady=8)

        # Security Alerts table
        alert_frame = tk.Frame(
            self.root,
            bg="#101827"
        )

        alert_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=5
        )

        alert_columns = (
            "Time",
            "Severity",
            "Category",
            "Registry Path",
            "Message"
        )

        self.alert_table = ttk.Treeview(
            alert_frame,
            columns=alert_columns,
            show="headings",
            height=5
        )

        alert_widths = {
            "Time": 145,
            "Severity": 80,
            "Category": 145,
            "Registry Path": 260,
            "Message": 350
        }

        for column in alert_columns:
            self.alert_table.heading(
            column,
            text=column
        )

        self.alert_table.column(
            column,
            width=alert_widths[column],
            minwidth=70
        )

        self.alert_table.pack(
            fill="both",
            expand=True
        )

    

    # Statistics cards
    def create_card(self, parent, title, value, column):

        card = tk.Frame(
            parent,
            bg="#1E293B",
            width=165,
            height=95
        )

        card.grid(
            row=0,
            column=column,
            padx=5
        )

        card.pack_propagate(False)

        tk.Label(
            card,
            text=title,
            bg="#1E293B",
            fg="#CBD5E1",
            font=("Arial", 9, "bold")
        ).pack(pady=10)

        value_label = tk.Label(
            card,
            text=value,
            bg="#1E293B",
            fg="white",
            font=("Arial", 22, "bold")
        )

        value_label.pack()

        return value_label

    # Start monitoring
    def start_monitoring(self):

        if self.monitor_process is not None:

            if self.monitor_process.poll() is None:
                messagebox.showinfo(
                    "Information",
                    "Monitoring is already running."
                )
                return

        monitor_file = BASE_DIR / "monitor.py"

        if not monitor_file.exists():
            messagebox.showerror(
                "Error",
                "monitor.py file not found!"
            )
            return

        try:

            self.monitor_process = subprocess.Popen(
                [sys.executable, str(monitor_file)],
                cwd=str(BASE_DIR)
            )

            self.status_label.config(
                text="● Monitoring Active",
                fg="#4ADE80"
            )

        except Exception as error:

            messagebox.showerror(
                "Error",
                str(error)
            )

    # Stop monitoring
    def stop_monitoring(self):

        if (
            self.monitor_process is not None
            and self.monitor_process.poll() is None
        ):

            try:
                self.monitor_process.terminate()
                self.monitor_process.wait(timeout=5)

            except subprocess.TimeoutExpired:
                self.monitor_process.kill()
                self.monitor_process.wait()

            except Exception as error:
                messagebox.showerror(
                    "Stop Error",
                    str(error)
                )

        self.monitor_process = None

        self.status_label.config(
            text="● Monitoring Stopped",
            fg="#F87171"
        )

        self.refresh_dashboard()

    # Read JSONL file
    def read_jsonl(self, file_path):

        records = []

        if not file_path.exists():
            return records

        try:

            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                for line in file:

                    if line.strip():

                        try:
                            records.append(json.loads(line))

                        except json.JSONDecodeError:
                            continue

        except OSError as error:
            print("File Read Error:", error)

        return records

    # Refresh dashboard data
    def refresh_dashboard(self):

        changes = self.read_jsonl(REGISTRY_LOGS)
        alerts = self.read_jsonl(ALERTS_FILE)

        self.total_changes = len(changes)
        self.total_alerts = len(alerts)

        added = sum(
            1 for item in changes
            if item.get("type") == "ADDED"
        )

        modified = sum(
            1 for item in changes
            if item.get("type") == "MODIFIED"
        )

        deleted = sum(
            1 for item in changes
            if item.get("type") == "DELETED"
        )

        self.change_label.config(
            text=str(self.total_changes)
        )

        self.alert_label.config(
            text=str(self.total_alerts)
        )

        self.added_label.config(
            text=str(added)
        )

        self.modified_label.config(
            text=str(modified)
        )

        self.deleted_label.config(
            text=str(deleted)
        )

        # Clear old table entries
        for item in self.table.get_children():
            self.table.delete(item)

        for item in self.alert_table.get_children():
            self.alert_table.delete(item)


        # Display registry changes
        for record in changes:

            timestamp = record.get(
                "timestamp", "N/A"
            )

            change_type = record.get(
                "type", "N/A"
            )

            registry_path = record.get(
                "registry_path", "N/A"
            )

            value_name = record.get(
                "value_name", "N/A"
            )

            old_value = record.get("old_value")
            new_value = record.get("new_value")

            details = (
                f"Old: {old_value} | New: {new_value}"
            )

            self.table.insert(
                "",
                "end",
                values=(
                    timestamp,
                    change_type,
                    registry_path,
                    value_name,
                    details
                )
            )

        # Display security alerts
        for alert in alerts:
            self.alert_table.insert(
                "",
                "end",
                values=(
                    alert.get("timestamp","N/A"),
                    alert.get("severity", "N/A"),
                    alert.get("registry_path","N/A"),
                    alert.get("message","N/A")
                )
            )

        # Update status
        if (
            self.monitor_process is not None
            and self.monitor_process.poll() is None
        ):

            self.status_label.config(
                text="● Monitoring Active",
                fg="#4ADE80"
            )

        else:

            self.status_label.config(
                text="● Monitoring Stopped",
                fg="#F87171"
            )

    # Automatic refresh
    def schedule_refresh(self):

        if self.refresh_job is not None:
            self.root.after_cancel(self.refresh_job)

        self.refresh_job = self.root.after(
            3000,
            self.auto_refresh
        )

    def auto_refresh(self):

        self.refresh_job = None

        self.refresh_dashboard()
        self.schedule_refresh()

    # Manual refresh
    def manual_refresh(self):

        self.refresh_dashboard()
        self.schedule_refresh()

    # Open logs
    def view_logs(self):

        if REGISTRY_LOGS.exists():
            os.startfile(str(REGISTRY_LOGS))

        elif ALERTS_FILE.exists():
            os.startfile(str(ALERTS_FILE))

        elif LOG_FILE.exists():
            os.startfile(str(LOG_FILE))

        else:
            messagebox.showwarning(
                "Logs",
                "No log file found!"
            )

    # Close dashboard safely
    def close_dashboard(self):

        if self.refresh_job is not None:
            self.root.after_cancel(self.refresh_job)

        self.stop_monitoring()
        self.root.destroy()


# Main program
if __name__ == "__main__":

    root = tk.Tk()

    app = RegistryDashboard(root)

    root.protocol(
        "WM_DELETE_WINDOW",
        app.close_dashboard
    )

    root.mainloop()