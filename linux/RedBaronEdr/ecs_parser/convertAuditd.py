import json
import sys
from datetime import datetime

def convert_audit_to_ecs(input_data):
    # Extract process arguments correctly
    title = input_data.get("process", {}).get("title", "")
    args = title.split()[1:] if title else []

    ecs_data = {
        "@timestamp": input_data.get("@timestamp", datetime.utcnow().isoformat() + "Z"),
        "event": {
            "category": input_data.get("category"),
            "type": input_data.get("ecs", {}).get("event", {}).get("type"),
            "action": input_data.get("summary", {}).get("action"),
            "outcome": input_data.get("result")
        },
        "user": {
            "id": input_data.get("user", {}).get("ids", {}).get("uid"),
            "name": input_data.get("user", {}).get("names", {}).get("uid"),
            "target": {
                "id": input_data.get("user", {}).get("ids", {}).get("auid"),
                "name": input_data.get("user", {}).get("names", {}).get("auid")
            },
            "group": {
                "id": input_data.get("user", {}).get("ids", {}).get("gid"),
                "name": input_data.get("user", {}).get("names", {}).get("gid")
            },
            "effective": {
                "id": input_data.get("user", {}).get("ids", {}).get("euid"),
                "name": input_data.get("user", {}).get("names", {}).get("euid")
            },
            "selinux": input_data.get("user", {}).get("selinux", {})
        },
        "process": {
            "name": input_data.get("process", {}).get("name"),
            "pid": input_data.get("process", {}).get("pid"),
            "ppid": input_data.get("process", {}).get("ppid"),
            "title": input_data.get("process", {}).get("title"),
            "executable": input_data.get("process", {}).get("exe"),
            "args": args,
            "arch": input_data.get("data", {}).get("arch"),
            "syscall": input_data.get("data", {}).get("syscall"),
            "tty": {
                "device": input_data.get("data", {}).get("tty")
            }
        },
        "tags": input_data.get("tags", []),
        "summary": input_data.get("summary", {})
    }
    return ecs_data

def main(input_file):
    try:
        with open(input_file, 'r') as f:
            input_data = json.load(f)
        ecs_json = convert_audit_to_ecs(input_data)
        print(json.dumps(ecs_json, indent=4))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_audit_to_ecs.py <input_json_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    main(input_file)
