import os
import random
import pandas as pd
from datetime import datetime, timedelta


def generate_dataset(output_dir="data"):
    os.makedirs(output_dir, exist_ok=True)
    random.seed(42)

    departments = ["IT Security", "Finance", "HR", "Engineering", "Operations", "Executive"]
    first_names = [
        "Rahul", "Priya", "Aman", "Neha", "Vikram", "Ananya", "Rohan", "Kavya",
        "Siddharth", "Meera", "Arjun", "Diya", "Karan", "Sneha", "Aditya", "Pooja",
        "Varun", "Ishita", "Nikhil", "Riya", "Manish", "Tara", "Deepak", "Nandini",
        "Abhishek", "Swati", "Harsh", "Shruti", "Gaurav", "Kriti", "Yash", "Aarti",
        "Pranav", "Divya", "Suresh", "Anjali", "Rajesh", "Pallavi", "Vivek", "Simran",
        "Tarun", "Sakshi", "Mohit", "Nidhi", "Akash", "Tanya", "Pankaj", "Bhavna",
        "Sandeep", "Garima"
    ]
    last_names = ["Sharma", "Verma", "Gupta", "Nair", "Mehta", "Kapoor", "Rao", "Malhotra", "Joshi", "Singh"]

    # 1. Generate 100 Employees (U001 to U100)
    employees = []
    for i in range(1, 101):
        uid = f"U{i:03d}"
        full_name = f"{first_names[(i - 1) % len(first_names)]} {last_names[(i - 1) % len(last_names)]}"
        dept = "IT Security" if i == 1 else ("Executive" if i == 12 else random.choice(departments))
        status = "Compromised" if i == 1 else ("High-Value" if i in [7, 12, 19, 45] else "Normal")
        employees.append({
            "user_id": uid,
            "name": full_name,
            "department": dept,
            "status": status
        })
    df_emp = pd.DataFrame(employees)

    # 2. Generate 150 Devices (D001 to D150)
    device_types = ["Workstation", "Laptop", "Jump-Server", "Database-Node", "Admin-Terminal"]
    devices = []
    for i in range(1, 151):
        did = f"D{i:03d}"
        owner = f"U{i:03d}" if i <= 100 else random.choice([f"U{x:03d}" for x in range(1, 101)])
        if i in [101, 102, 103]:
            dtype = "Jump-Server"
        elif i in [145, 148, 150]:
            dtype = "Database-Node"
        else:
            dtype = random.choice(["Workstation", "Laptop", "Admin-Terminal"])
        devices.append({
            "device_id": did,
            "device_type": dtype,
            "owner": owner
        })
    df_dev = pd.DataFrame(devices)

    # 3. Generate Login Logs (Normal daily activity + Multi-hop Attack Chain)
    logs = []
    base_time = datetime(2026, 11, 26, 8, 0, 0)
    internal_ips = [f"10.24.{random.randint(1, 12)}.{random.randint(10, 250)}" for _ in range(45)]
    shared_office_wifi = "172.16.0.1"  # High-noise shared gateway IP

    # Normal background logins (260 events)
    for _ in range(260):
        u_idx = random.randint(2, 100)
        uid = f"U{u_idx:03d}"
        did = f"D{u_idx:03d}" if random.random() < 0.78 else f"D{random.randint(1, 130):03d}"
        ip = shared_office_wifi if random.random() < 0.22 else random.choice(internal_ips)
        ts = base_time + timedelta(minutes=random.randint(0, 540))
        logs.append({
            "user_id": uid,
            "device_id": did,
            "ip_address": ip,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M"),
            "login_type": "Normal-SSO",
            "is_shared_gateway": ip == shared_office_wifi
        })

    # Embedded Multi-Hop Lateral Movement Chain starting from U001 (Rahul Sharma)
    attack_events = [
        ("U001", "D001", "10.24.9.99", "09:10", "Suspicious-Token"),
        ("U001", "D101", "10.24.9.99", "09:18", "Lateral-SSH"),        # U001 pivots to Jump-Server D101
        ("U004", "D101", "10.24.4.12", "09:26", "Shared-Session"),     # Neha (U004) logs into compromised D101
        ("U004", "D004", "10.24.4.12", "09:40", "Credential-Dump"),    # U004 returns to D004
        ("U007", "D004", "10.24.7.88", "10:05", "Remote-RDP"),         # Vikram (U007) accesses D004
        ("U007", "D145", "10.24.7.88", "10:22", "Privilege-Esc"),      # U007 pivots to Database-Node D145
        ("U012", "D145", "10.24.1.5",  "10:45", "Admin-Query"),        # Executive Kavya (U012) accesses D145
        ("U012", "D150", "10.24.1.5",  "11:02", "Exfiltration-Prep")   # Reaches Core Vault D150
    ]

    for uid, did, ip, t_str, ltype in attack_events:
        logs.append({
            "user_id": uid,
            "device_id": did,
            "ip_address": ip,
            "timestamp": f"2026-11-26 {t_str}",
            "login_type": ltype,
            "is_shared_gateway": False
        })

    df_logs = pd.DataFrame(logs).sort_values("timestamp")

    df_emp.to_csv(os.path.join(output_dir, "employees.csv"), index=False)
    df_dev.to_csv(os.path.join(output_dir, "devices.csv"), index=False)
    df_logs.to_csv(os.path.join(output_dir, "login_logs.csv"), index=False)
    print(f"Generated {len(df_emp)} employees, {len(df_dev)} devices, and {len(df_logs)} login logs in '{output_dir}/'.")


if __name__ == "__main__":
    generate_dataset()