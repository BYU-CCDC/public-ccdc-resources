#!/usr/bin/env python3

import argparse
import hashlib
import math
import sys
import subprocess
import os
import urllib.request
import ssl
from pathlib import Path
from typing import List

NUM_WORDS = 5

DEFAULT_WORDLIST = "wordlist.txt"
WORDLIST_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening/wordlist.txt"

DEFAULT_HOME_ROOT = "/home"
DEFAULT_USERS_TXT = "users.txt"

EXCLUDED_USERS = {"root", "ccdcuser1", "ccdcuser2"}

class PasswordGenerator:
    def __init__(self, wordlist_path: str):
        self._ensure_wordlist(wordlist_path)
        self.wordlist = self._load_wordlist(wordlist_path)
        print(f"[*] Loaded {len(self.wordlist)} words from wordlist")

    def _ensure_wordlist(self, path: str) -> None:
        if os.path.exists(path):
            return
        print(f"[*] Wordlist '{path}' not found. Attempting download from BYU-CCDC...")
        try:
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(WORDLIST_URL, context=context) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())
            print("[+] Download successful.")
        except Exception as e:
            print(f"\n[!] Error downloading wordlist: {e}")
            sys.exit(1)

    def _load_wordlist(self, wordlist_path: str) -> List[str]:
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                words = [line.strip() for line in f if line.strip()]
            if not words:
                raise ValueError("Wordlist is empty")
            return words
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            sys.exit(1)

    def minmax_scale(self, x):
        # https://en.wikipedia.org/wiki/Feature_scaling#Rescaling_(min-max_normalization)
        MIN=0x0000
        MAX=0xffff
        TARGET_MIN=0
        TARGET_MAX=len(self.wordlist)-1
        # round down to nearest integer
        return math.floor(((TARGET_MAX-TARGET_MIN)*(x-MIN)) / (MAX - MIN) + TARGET_MIN)

    def generate_password(self, secret: str, username: str) -> str:
        combined = secret + username
        hash_hex = hashlib.md5(combined.encode("utf-8")).hexdigest()

        parts: List[str] = []
        for i in range(NUM_WORDS):
            start = i * 4
            end = start + 4
            if end > len(hash_hex):
                break
                
            hex_chunk = hash_hex[start:end]
            hex_value = int(hex_chunk, 16)
            idx = self.minmax_scale(hex_value)
            parts.append(self.wordlist[idx])

        return "-".join(parts) + "1"

def discover_users_from_home(home_root: str) -> List[str]:
    root = Path(home_root)
    if not root.exists() or not root.is_dir():
        return []
    users: List[str] = []
    try:
        for p in sorted(root.iterdir()):
            if p.is_dir() and not p.name.startswith(".") and p.name not in EXCLUDED_USERS:
                users.append(p.name)
    except OSError:
        pass
    return users

def write_lines(path: str, lines: List[str]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
    except OSError as e:
        print(f"[!] Error writing to {path}: {e}")

def prompt_secret() -> str:
    while True:
        s = input("Secret seed: ").strip()
        if s: return s

def setup_comp_users():
    """Ensures ccdcuser1 (Admin) and ccdcuser2 (User) exist and prompts for manual passwords."""
    print("\n[+] Setting up competition users...")

    print("\nConfiguring ccdcuser1 (Admin)")
    if subprocess.run(["id", "ccdcuser1"], capture_output=True).returncode != 0:
        print("[*] Creating ccdcuser1...")
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", "ccdcuser1"])
    else:
        print("[*] ccdcuser1 already exists.")
    
    subprocess.run(["usermod", "-aG", "sudo", "ccdcuser1"], stderr=subprocess.DEVNULL)
    subprocess.run(["usermod", "-aG", "wheel", "ccdcuser1"], stderr=subprocess.DEVNULL)
    
    print("[?] Please manually enter the password for ccdcuser1:")
    subprocess.run(["passwd", "ccdcuser1"])

    print("\nConfiguring ccdcuser2 (Standard)")
    if subprocess.run(["id", "ccdcuser2"], capture_output=True).returncode != 0:
        print("[*] Creating ccdcuser2...")
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", "ccdcuser2"])
    else:
        print("[*] ccdcuser2 already exists.")
    
    print("[?] Please manually enter the password for ccdcuser2:")
    subprocess.run(["passwd", "ccdcuser2"])
    print("\n[+] Competition users setup complete.")

def apply_passwords_to_system(user_pass_pairs: List[str]) -> None:
    if os.geteuid() != 0:
        print("\n[!] WARNING: Not root. Skipping system application.")
        return

    data = "\n".join(user_pass_pairs)
    print(f"\n[?] Ready to apply algorithmic passwords for {len(user_pass_pairs)} users.")
    if input("Type 'YES' to apply changes: ").strip() != "YES":
        print("[*] Aborted.")
        return

    try:
        subprocess.run(
            ["chpasswd"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        print(f"\n[+] Success! {len(user_pass_pairs)} passwords updated.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST)
    parser.add_argument("--user", action="store_true")
    parser.add_argument("--home-root", default=DEFAULT_HOME_ROOT)
    parser.add_argument("--users-out", default=DEFAULT_USERS_TXT)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script requires root privileges to function correctly.")
        sys.exit(1)

    generator = PasswordGenerator(args.wordlist)

    if args.user:
        print("\nSingle User Mode")
        u = input("Username: ").strip()
        if u and u not in EXCLUDED_USERS:
            s = prompt_secret()
            pw = generator.generate_password(s, u)
            print(f"\n[+] Generated password for {u}: {pw}")
            if input("Apply? (y/N): ").lower().startswith('y'):
                apply_passwords_to_system([f"{u}:{pw}"])
        else:
            print("[!] Invalid or excluded user.")
        return

    setup_comp_users()

    print("\nBulk Password Rotation")
    users = discover_users_from_home(args.home_root)
    
    if not users:
        print("[!] No other users found in /home.")
    else:
        write_lines(args.users_out, users) 
        print(f"[*] Identified {len(users)} users to rotate (excluding ccdcuser1/2/root).")
        
        secret = prompt_secret()
        
        pairs = []
        print("\n[+] Generated Credentials:")
        for u in users:
            pw = generator.generate_password(secret, u)
            print(f"{u}:{pw}")
            pairs.append(f"{u}:{pw}")
        
        apply_passwords_to_system(pairs)
        
    print("\n")
    print("WARNING: ROOT PASSWORD MUST BE CHANGED IF YOU DIDN'T ALREADY!!!")
    print("\n")
    
if __name__ == "__main__":
    main()
