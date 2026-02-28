import sys
def extract_password_policies(file_path):
    password_policies = {}
    current_password = None

    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("PASSWORD POLICY CHECKS FOR"):
                current_password = line.split()[-1].strip().lower()
                password_policies[current_password] = {}
            elif line.startswith("[*]"):
                key, value = map(str.strip, line[4:].split(":", 1))
                password_policies[current_password][key] = value.lower() == "true"

    return password_policies

def print_formatted_result(password_policies, policy_name):
    print(f"[*] {policy_name}")
    for password, policies in password_policies.items():
        try:
            print(f"{password}, {policies[policy_name]}")
        except KeyError:
            print(f"{password}, False")

if __name__ == "__main__":
    print("Usage: python pwpol_summarize.py <file_path>")
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = "output.txt"
    password_policies = extract_password_policies(file_path)
    for policy_name in password_policies[next(iter(password_policies))]:
        print_formatted_result(password_policies, policy_name)
