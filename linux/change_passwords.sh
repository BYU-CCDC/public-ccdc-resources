#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Function to change all user passwords to the given password
change_all_passwords() {
  local new_password="$1"
  local user_list

  # Get a list of all user accounts (excluding system users)
  if ! user_list=$(getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}'); then
    echo "Error: Unable to retrieve user list."
    exit 1
  fi

  # Loop through each user and change their password
  for user in $user_list; do
    if ! echo "$user:$new_password" | chpasswd; then
      echo "Failed to change password for $user."
    else
      echo "Password for $user has been changed."
    fi
  done
}

# Ask the user for the new password
read -p "Enter the new password for all users: " -s new_password
echo

# Ask the user to confirm the password
read -p "Retype the new password to confirm: " -s confirm_password
echo

if [ "$new_password" != "$confirm_password" ]; then
  echo "Passwords do not match. Passwords were not changed."
  exit 1
else
  # Call the function to change all user passwords
  change_all_passwords "$new_password"
fi
