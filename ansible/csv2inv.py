#!/usr/bin/env python3

import csv
import sys

def csv_to_ansible_inventory(csv_file_path, ini_file_path):
    """
    Reads a CSV file with rows like 'ip|username|password' and writes
    out a hosts.ini file where each IP is its own section.
    Variables are placed on separate lines for easy updates.
    """
    with open(csv_file_path, 'r', newline='') as csvfile, open(ini_file_path, 'w') as inifile:
        reader = csv.reader(csvfile, delimiter=',')

        # For each row in the CSV, output an INI section
        for row in reader:
            if not row or len(row) < 3:
                continue

            ip, uname, pw = row[0].strip(), row[1].strip(), row[2].strip()

            # A bracketed section named after the IP
            inifile.write(f"[{ip}]\n")
            inifile.write(f"ansible_host={ip}\n")
            inifile.write(f"ansible_user={uname}\n")
            inifile.write(f"ansible_password={pw}\n")
            inifile.write(f"ansible_become_password={pw}\n\n")

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
