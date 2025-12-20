import json
import sys
from datetime import datetime

def convert_to_ecs(input_data):
    ecs_data = {
        "@timestamp": input_data.get("UpdatedTime", datetime.utcnow().isoformat() + "Z"),
        "host": {
            "name": input_data.get("HostName"),
            "id": str(input_data.get("UID", 0)),
            "os": {
                "platform": "linux"
            }
        },
        "process": {
            "name": input_data.get("ProcessName"),
            "pid": input_data.get("PID"),
            "ppid": input_data.get("HostPPID"),
            "args": input_data.get("Resource", "").split(),
            "executable": input_data.get("ProcessName"),
            "working_directory": input_data.get("Cwd"),
            "tty": {
                "device": input_data.get("TTY")
            },
            "parent": {
                "name": input_data.get("ParentProcessName"),
                "pid": input_data.get("HostPPID")
            }
        },
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": input_data.get("Data"),
            "outcome": "success" if input_data.get("Result") == "Passed" else "failure"
        },
        "user": {
            "id": str(input_data.get("UID"))
        }
    }
    return ecs_data

def main(input_file):
    try:
        with open(input_file, 'r') as f:
            input_data = json.load(f)
        ecs_json = convert_to_ecs(input_data)
        print(json.dumps(ecs_json, indent=4))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_to_ecs.py <input_json_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    main(input_file)
