#!/bin/bash

# Below is a valid bash script that is also a valid awk script (albeit one that does nothing)
# Its only purpose is to run this file as an awk script with the proper `ss` command piped in
# on the off chance it isn't run properly

#region bash
sh -c "ss -napH4 | awk -f $BASH_SOURCE" {0..0}
"exit" {0..0}
#endregion bash

# Tested `ss` options:
# - napOH4
# - napH4

# Configuration
BEGIN {
  # Competition Configuration

  # Space-seperated list of subnets that are unrestricted (VPN, white team, etc.)
  UNRESTRICTED_SUBNETS = "10.128.XXX.0/24";

  EXTERNAL_SUBNET = "10.120.XXX.0/24";  # UNUSED

  # Space-seperated list of DNS server IPs
  DNS_SERVERS = "192.168.XXX.1 192.168.XXX.2";

  # Script Configuration
  IPTABLES_CMD = "iptables";
  DEFAULT_INPUT_CHAIN = "INPUT";
  DEFAULT_OUTPUT_CHAIN = "OUTPUT";
  
  # Logging
  # 1 : Debug
  # 2 : Info
  # 3 : Warning
  # 4 : Error
  LOG_LEVEL = 2;

  # Set to 1 to skip the warning at the beginning of the script
  SKIP_PROMPT = 0;

  # Space-seperated list of inbound connection types
  # Default: "LISTEN" for TCP and "UNCONN" for UDP
  INBOUND_CONNECTION_TYPES = "LISTEN";

  # Space-seperated list of outbound connection types
  # Default: "ESTAB" for TCP and UDP
  OUTBOUND_CONNECTION_TYPES = "ESTAB";

  # Port Whitelist
  # Used to only allow ports that should have a service
  INBOUND_PORT_WHITELIST  = "21 22 80 443 53"
  OUTBOUND_PORT_WHITELIST = INBOUND_PORT_WHITELIST

  # Colored output
  COLORED_OUTPUT = 1;
}

function keyify(arr) {
  for(i in arr) arr[arr[i]] = 1;
}

# Variables / Constants
BEGIN {
  # Get arrays from config vars
  split(INBOUND_CONNECTION_TYPES, INBOUND_CONNECTION_TYPES_ARRAY);
  keyify(INBOUND_CONNECTION_TYPES_ARRAY);
  split(OUTBOUND_CONNECTION_TYPES, OUTBOUND_CONNECTION_TYPES_ARRAY);
  keyify(OUTBOUND_CONNECTION_TYPES_ARRAY);
  
  split(INBOUND_PORT_WHITELIST, INBOUND_PORT_WHITELIST_ARRAY);
  keyify(INBOUND_PORT_WHITELIST_ARRAY);
  split(OUTBOUND_PORT_WHITELIST, OUTBOUND_PORT_WHITELIST_ARRAY);
  keyify(OUTBOUND_PORT_WHITELIST_ARRAY);

  # Declare array of colors
  delete COLORS[0];

  # Fill the array full of delicious colors
  COLORS["black"]         = 30;
  COLORS["red"]           = 31;
  COLORS["green"]         = 32;
  COLORS["yellow"]        = 33;
  COLORS["blue"]          = 34;
  COLORS["magenta"]       = 35;
  COLORS["cyan"]          = 36;
  COLORS["white"]         = 37;
  COLORS["default"]       = 39;

  COLORS["gray"]          = 90;
  COLORS["brightRed"]     = 91;
  COLORS["brightGreen"]   = 92;
  COLORS["brightYellow"]  = 93;
  COLORS["brightBlue"]    = 94;
  COLORS["brightMagenta"] = 95;
  COLORS["brightCyan"]    = 96;
  COLORS["brightWhite"]   = 97;

  # Declare array of log colors
  delete LOG_LEVEL_COLORS[0];

  LOG_LEVEL_COLORS["DEBUG"]   = "magenta";
  LOG_LEVEL_COLORS["INFO"]    = "cyan";
  LOG_LEVEL_COLORS["WARNING"] = "yellow";
  LOG_LEVEL_COLORS["ERROR"]   = "red";

  # Log Level Names
  delete LOG_LEVEL_NAMES[0];

  LOG_LEVEL_NAMES["DEBUG"]   = 1;
  LOG_LEVEL_NAMES["INFO"]    = 2;
  LOG_LEVEL_NAMES["WARNING"] = 3;
  LOG_LEVEL_NAMES["ERROR"]   = 4;
}

function setColor(color) {
  if(!COLORED_OUTPUT)
    return "";
  else if(color == "")
    return "\033[39m";
  else
    return sprintf("\033[%dm", COLORS[color]);
}

function colored(color, message) {
  return setColor(color) message setColor();
}

function printLog(level, message) {
  # If the chosen log level is above the level of this message, don't display it
  if(LOG_LEVEL_NAMES[level] < LOG_LEVEL) return;
  # The 17 comes from the length of the ANSI escape codes for color plus the max log level length (7 + 10)
  printf("%*s: %s\n", COLORED_OUTPUT ? 17 : 7, colored(LOG_LEVEL_COLORS[level], level), message) > "/dev/tty";
}

function formatPort(port, proto, name) {
  return colored("yellow", sprintf("%5d", port)) "/" proto " (" colored("blue", name) ")";
}

# Base Ruleset and housekeeping
BEGIN {
  "tty" | getline isTTY;
  if(isTTY != "not a tty")
    printLog("WARNING", "TTY stdin detected. This script is designed to take the output from `ss -napOH4`");

  if(!SKIP_PROMPT) {
    # This is a prompt, not a log
    print(colored("red", "WARNING") ": Existing rules for the " DEFAULT_INPUT_CHAIN " and " DEFAULT_OUTPUT_CHAIN " chains will be flushed!\nPress RETURN to continue.") > "/dev/tty";
    getline < "/dev/tty";
  }

  # Remove the previous ruleset
  printLog("INFO", "Flushing " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-F", DEFAULT_INPUT_CHAIN);
  printLog("INFO", "Flushing " DEFAULT_OUTPUT_CHAIN);
  print(IPTABLES_CMD, "-F", DEFAULT_OUTPUT_CHAIN);

  # Loopback traffic
  printLog("INFO", "Accepting loopback traffic on " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN,  "-i lo -j ACCEPT");
  printLog("INFO", "Accepting loopback traffic on " DEFAULT_OUTPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_OUTPUT_CHAIN, "-o lo -j ACCEPT");

  # Connection Tracking
  printLog("INFO", "Enabling connection tracking on " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN,  "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
  printLog("INFO", "Enabling connection tracking on " DEFAULT_OUTPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_OUTPUT_CHAIN, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");

  # ICMP
  printLog("INFO", "Accepting ICMP traffic from " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN, "-p icmp -j ACCEPT");

  # Outbound to the internet
  # print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN, "-d", EXTERNAL_SUBNET, "-j ACCEPT");

  # DNS
  split(DNS_SERVERS, _DNS_SERVERS);
  for(server in _DNS_SERVERS) {
    printLog("INFO", "New outbound rule - " sprintf("%15s", _DNS_SERVERS[server]) ":" colored("yellow", sprintf("%5d", 53)) "/udp (" colored("blue", "DNS") ")");
    print(IPTABLES_CMD, "-A", DEFAULT_OUTPUT_CHAIN, "-p udp -m udp --dport 53 -d", _DNS_SERVERS[server], "-j ACCEPT");
  }

  split(UNRESTRICTED_SUBNETS, _UNRESTRICTED_SUBNETS);
  for(subnet in _UNRESTRICTED_SUBNETS) {
    printLog("INFO", "New inbound rule - " sprintf("%18s", _UNRESTRICTED_SUBNETS[subnet]) " (" colored("blue", "unrestricted subnet") ")");
    print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN, "-d", _UNRESTRICTED_SUBNETS[subnet], "-j ACCEPT");
  }

  # Initialize tables of added rules
  delete INPUT_RULES[0];
  delete OUTPUT_RULES[0];
}

function extractIP(string) {
  if(match(string, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
    return substr(string,RSTART,RLENGTH);
  }
  return "";
}

# Runs before other rules to process common fields
{
  # Process info
  if(match($7, "\"[^\"]+\""))
    name = substr($7,RSTART + 1,RLENGTH - 2);
  else
    name = "";
     
  # Remote ports and IPs
  split($6, remote, ":");
  remoteIP   = extractIP(remote[1]);
  if(remoteIP == "")
    printLog("WARNING", "Invalid remote IP for " colored("yellow", $6) " (" colored("blue", name) ")");
  if(remote[2] != "*" && (remote[2] < 1 || remote[2] > 65535))
    printLog("WARNING", "Invalid remote port for " colored("yellow", $6) " (" colored("blue", name) ")");

  # Local ports and IPs
  split($5, local, ":");
  localIP   = extractIP(local[1]);
  if(localIP == "")
    printLog("WARNING", "Invalid local IP for "   colored("yellow", $5) " (" colored("blue", name) ")");
  if(local[2] != "*" && (local[2] < 1 || local[2] > 65535))
    printLog("WARNING", "Invalid local port for " colored("yellow", $5) " (" colored("blue", name) ")");
}

# Listening processes
$2 in INBOUND_CONNECTION_TYPES_ARRAY {
  # Skip if the rule has already been created
  if(INPUT_RULES[local[2] "/" $1]) next;

  # Skip adding the rule if the port isn't in the whitelist
  if(local[2] in INBOUND_PORT_WHITELIST_ARRAY == 0) {
    printLog("WARNING", "Inbound connection " formatPort(local[2], $1, name) " not in whitelist, skipping.");
    next;
  }

  # Comment (if process info is present)
  if(name) comment = "-m comment --comment \"" name "\"";
  else     comment = ""

  # Actual command
  print(IPTABLES_CMD " -A " DEFAULT_INPUT_CHAIN " -p " $1 " -m " $1 " --dport " local[2] " " comment " -j ACCEPT");

  # Log
  printLog("INFO", "New inbound rule - " formatPort(local[2], $1, name));

  # Record the port and protocol so we can avoid duplicating rules
  INPUT_RULES[local[2] "/" $1] = 1;
}

# Established connections
$2 in OUTBOUND_CONNECTION_TYPES_ARRAY {
  # Skip if the rule has already been created
  if(remoteIP) {
    if(OUTPUT_RULES[$6 "/" $1]) next;
  } else {
    if(OUTPUT_RULES[remote[2] "/" $1]) next;
  }
  
  # Skip adding the rule if the port isn't in the whitelist
  if(remote[2] in OUTBOUND_PORT_WHITELIST_ARRAY == 0) {
    printLog("WARNING", "Outbound connection " formatPort(remote[2], $1, name) " not in whitelist, skipping.");
    next;
  }

  # Destination IP
  if(remoteIP) remoteIPMatcher = "-d " remoteIP;
  else         remoteIPMatcher = ""

  # Comment (if process info is present)
  if(name) comment = "-m comment --comment \"" name "\"";
  else     comment = ""

  # iptables command
  print(IPTABLES_CMD " -A " DEFAULT_OUTPUT_CHAIN " -p " $1 "-m " $1 " --dport " remote[2] " " remoteIPMatcher " -j ACCEPT");

  # Log the rule creation
  printLog("INFO", "New outbound rule - " sprintf("%15s", remoteIP) ":" formatPort(remote[2], $1, name));

  # Record the port, IP, and protocol so we can avoid duplicating rules
  if(remoteIP) OUTPUT_RULES[$6 "/" $1] = 1;
  else         OUTPUT_RULES[remote[2] "/" $1] = 1;
}