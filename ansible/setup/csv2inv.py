#!/usr/bin/env python3

import csv
import sys

def csv_to_ansible_inventory(csv_file_path, ini_file_path):
    """
    Reads a CSV file with rows like:
      ip|username|password
    And writes out a single-line format for each host, e.g.:
      192.168.4.90 ansible_user=sysadmin ansible_password=password2 ansible_become_password=password2
    """
    with open(csv_file_path, 'r', newline='') as csvfile, open(ini_file_path, 'w') as inifile:
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            if len(row) < 3:
                continue  # Skip any malformed lines

            ip, uname, pw = row[0].strip(), row[1].strip(), row[2].strip()
            inifile.write(f"{ip} ansible_user={uname} ansible_password={pw} ansible_become_password={pw}\n")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_csv> <output_ini>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    ini_file_path = sys.argv[2]

    csv_to_ansible_inventory(csv_file_path, ini_file_path)
    print(f"Hosts INI file written to: {ini_file_path}")

if __name__ == "__main__":
    main()
