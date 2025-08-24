#!/usr/bin/env python3
import os
import re
import glob
from pathlib import Path


def analyze_logs():
    log_dir = "/app/logs"
    print(f"Analyzing logs in: {log_dir}")

    # Check if log directory exists
    if not os.path.exists(log_dir):
        print(f"Log directory {log_dir} not found!")
        print("Available files:", os.listdir('/app'))
        return

    # Analyze each log file
    for log_file in Path(log_dir).glob("*.log"):
        print(f"\nAnalyzing {log_file.name}:")

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                print(f"Found {len(lines)} lines")

                # Simple analysis
                ssh_failures = [line for line in lines if "Failed password" in line]
                http_requests = [line for line in lines if "GET" in line or "POST" in line]
                sql_injections = [line for line in lines if "union" in line.lower() or "select" in line.lower()]

                if ssh_failures:
                    print(f"⚠️  Found {len(ssh_failures)} SSH failure attempts")
                    for failure in ssh_failures[:3]:  # Show first 3
                        print(f"   - {failure.strip()}")

                if http_requests:
                    print(f"🌐 Found {len(http_requests)} HTTP requests")

                if sql_injections:
                    print(f"🚨 Found {len(sql_injections)} possible SQL injection attempts")
                    for attempt in sql_injections[:3]:
                        print(f"   - {attempt.strip()}")

        except Exception as e:
            print(f"Error reading {log_file}: {e}")


if __name__ == "__main__":
    print("Starting Windows-compatible log analyzer...")
    analyze_logs()
    print("Log analysis complete!")