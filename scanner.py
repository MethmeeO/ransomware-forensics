# Basic File Forensics Tool
import os
import hashlib
from datetime import datetime

SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.ps1']

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return "Could not calculate hash"

def analyze_folder(folder_path):
    report = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            size = os.path.getsize(file_path)
            created = datetime.fromtimestamp(os.path.getctime(file_path))
            modified = datetime.fromtimestamp(os.path.getmtime(file_path))
            file_hash = get_file_hash(file_path)
            status = "SAFE"
            reason = "No suspicious behavior detected"
            if ext in SUSPICIOUS_EXTENSIONS:
                status = "SUSPICIOUS"
                reason = "Executable or script file detected"
            elif size > 50 * 1024 * 1024:
                status = "SUSPICIOUS"
                reason = "Very large file size"
            report.append(f"""File Name: {file}\nPath: {file_path}\nSize: {size / 1024:.2f} KB\nCreated: {created}\nModified: {modified}\nSHA256 Hash: {file_hash}\nStatus: {status}\nReason: {reason}\n--------------------------------------\n""")
    return report

folder = input("Enter folder path to scan: ")
results = analyze_folder(folder)

with open("report.txt", "w") as r:
    for line in results:
        r.write(line)

print("Scan complete. Report saved as report.txt")
