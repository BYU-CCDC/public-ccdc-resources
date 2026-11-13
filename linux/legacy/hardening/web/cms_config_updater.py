#!/usr/bin/env python3

import argparse
import pathlib
import re
import shutil
import sys
from datetime import datetime

UPDATED = 0
UNCHANGED = 10


def create_backup(path: pathlib.Path) -> pathlib.Path:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_name = f"{path.name}.bak.{timestamp}"
    backup_path = path.with_name(backup_name)
    shutil.copy2(path, backup_path)
    return backup_path


def escape_for_quote(value: str, quote: str) -> str:
    value = value.replace("\\", "\\\\")
    if quote == "'":
        value = value.replace("'", "\\'")
    elif quote == '"':
        value = value.replace('"', '\\"')
    return value


def update_wordpress(path: pathlib.Path, args: argparse.Namespace) -> bool:
    text = path.read_text()
    original = text

    replacements = [
        ("DB_NAME", args.db_name),
        ("DB_USER", args.db_user),
        ("DB_HOST", args.db_host),
        ("DB_PASSWORD", args.db_pass),
    ]

    for key, value in replacements:
        if not value:
            continue
        pattern = re.compile(
            "(define\\(\\s*(['\"])" + re.escape(key) + "\\2\\s*,\\s*)(['\"])(.*?)(\\3\\s*\\);",
            re.DOTALL,
        )

        def repl(match: re.Match[str]) -> str:
            prefix, _, quote, _, suffix = match.groups()
            escaped = escape_for_quote(value, quote)
            return f"{prefix}{quote}{escaped}{quote}{suffix}"

        text = pattern.sub(repl, text)

    if text == original:
        return False

    create_backup(path)
    path.write_text(text)
    return True


def update_prestashop(path: pathlib.Path, args: argparse.Namespace) -> bool:
    text = path.read_text()
    original = text

    mapping = {
        "database_name": args.db_name,
        "database_user": args.db_user,
        "database_host": args.db_host,
        "database_password": args.db_pass,
        "_DB_NAME_": args.db_name,
        "_DB_USER_": args.db_user,
        "_DB_SERVER_": args.db_host,
        "_DB_PASSWD_": args.db_pass,
    }

    for key, value in mapping.items():
        if not value:
            continue
        array_pattern = re.compile(
            "(['\"])" + re.escape(key) + "\\1(\\s*=>\\s*)(['\"])(.*?)(\\3)",
            re.DOTALL,
        )

        def array_repl(match: re.Match[str]) -> str:
            quote_key, spacer, quote_value, _, _ = match.groups()
            escaped = escape_for_quote(value, quote_value)
            return f"{quote_key}{key}{quote_key}{spacer}{quote_value}{escaped}{quote_value}"

        text = array_pattern.sub(array_repl, text)

        define_pattern = re.compile(
            "(define\\(\\s*(['\"])" + re.escape(key) + "\\2\\s*,\\s*)(['\"])(.*?)(\\3\\s*\\);",
            re.DOTALL,
        )

        def define_repl(match: re.Match[str]) -> str:
            prefix, _, quote, _, suffix = match.groups()
            escaped = escape_for_quote(value, quote)
            return f"{prefix}{quote}{escaped}{quote}{suffix}"

        text = define_pattern.sub(define_repl, text)

    if text == original:
        return False

    create_backup(path)
    path.write_text(text)
    return True


def update_env(path: pathlib.Path, args: argparse.Namespace) -> bool:
    text = path.read_text()
    original = text

    def replace_line(key: str, value: str) -> None:
        nonlocal text
        if not value:
            return
        pattern = re.compile(rf"^(\\s*{re.escape(key)}\\s*=\\s*)(.*)$", re.MULTILINE)

        def repl(match: re.Match[str]) -> str:
            prefix, existing = match.groups()
            existing = existing.strip()
            if existing.startswith("'") and existing.endswith("'") and len(existing) >= 2:
                escaped = escape_for_quote(value, "'")
                return f"{prefix}'{escaped}'"
            if existing.startswith('"') and existing.endswith('"') and len(existing) >= 2:
                escaped = escape_for_quote(value, '"')
                return f"{prefix}\"{escaped}\""
            return f"{prefix}{value}"

        text = pattern.sub(repl, text)

    replace_line("DB_DATABASE", args.db_name)
    replace_line("DB_USERNAME", args.db_user)
    replace_line("DB_HOST", args.db_host)
    replace_line("DB_PASSWORD", args.db_pass)

    if text == original:
        return False

    create_backup(path)
    path.write_text(text)
    return True


def update_joomla(path: pathlib.Path, args: argparse.Namespace) -> bool:
    text = path.read_text()
    original = text

    mapping = {
        "db": args.db_name,
        "user": args.db_user,
        "host": args.db_host,
        "password": args.db_pass,
    }

    for key, value in mapping.items():
        if not value:
            continue
        patterns = [
            re.compile(rf"(public \\${key}\\s*=\\s*)(['\"])(.*?)(\\2)(;)", re.DOTALL),
            re.compile(rf"(\\${key}\\s*=\\s*)(['\"])(.*?)(\\2)(;)", re.DOTALL),
        ]

        for pattern in patterns:
            def repl(match: re.Match[str]) -> str:
                prefix, quote, _, _, suffix = match.groups()
                escaped = escape_for_quote(value, quote)
                return f"{prefix}{quote}{escaped}{quote}{suffix}"

            text = pattern.sub(repl, text)

    if text == original:
        return False

    create_backup(path)
    path.write_text(text)
    return True


UPDATE_HANDLERS = {
    "wordpress": update_wordpress,
    "prestashop": update_prestashop,
    "joomla": update_joomla,
    "env": update_env,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update CMS database credentials.")
    parser.add_argument("mode", choices=UPDATE_HANDLERS.keys())
    parser.add_argument("file")
    parser.add_argument("--db-name")
    parser.add_argument("--db-user")
    parser.add_argument("--db-host")
    parser.add_argument("--db-pass")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = pathlib.Path(args.file)

    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    handler = UPDATE_HANDLERS[args.mode]

    try:
        changed = handler(path, args)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to update {path}: {exc}", file=sys.stderr)
        return 1

    if changed:
        print("UPDATED")
        return UPDATED

    print("UNCHANGED")
    return UNCHANGED


if __name__ == "__main__":
    sys.exit(main())
