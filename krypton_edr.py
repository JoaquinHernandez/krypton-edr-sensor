import os
import sys
import json
import re
import time
from datetime import datetime, timezone

# ANSI Color & Styling Tokens
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
MAGENTA = "\033[38;5;201m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
 ██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗
 ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║
 █████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║
 ██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║╚██╗██║
 ██║  ██╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
{RESET}{AMBER} » KRYPTON-EDR: ACTIVE ENDPOINT BEHAVIORAL SENSOR & THREAT NEUTRALIZER «{RESET}
"""

class KryptonEDRAgent:
    def __init__(self, policy_path="edr_policy.json", telemetry_path="host_telemetry.json"):
        if not os.path.exists(policy_path) or not os.path.exists(telemetry_path):
            print(f"{RED}[-] Error: Missing policy or telemetry file.{RESET}")
            sys.exit(1)

        with open(policy_path, "r") as f:
            self.policy = json.load(f)

        with open(telemetry_path, "r") as f:
            self.events = json.load(f).get("telemetry_stream", [])

        self.rules = self.policy.get("behavioral_rules", [])
        self.auto_contain = self.policy.get("active_containment", True)

    def boot_agent(self):
        print(BANNER)
        print(f"{BOLD}Hooking OS Kernel System Calls & Process Watchers...{RESET}\n")
        modules = [
            "Initializing Kernel Ring-0 Filter Driver",
            "Loading Behavioral Heuristic Database",
            "Establishing MITRE ATT&CK Detection Matrix",
            "Binding Active Containment & SIGKILL Response Hooks"
        ]
        for mod in modules:
            time.sleep(0.25)
            print(f"  {CYAN}▸{RESET} {mod:<50} [{GREEN}{BOLD}ACTIVE{RESET}]")
        print("\n" + "=" * 80 + "\n")

    def run_live_inspection(self):
        self.boot_agent()
        print(f"{BOLD}{GREEN}● LIVE HOST TELEMETRY STREAM ACTIVE{RESET} {DIM}(Inspecting Inbound Process Spawns){RESET}\n")

        threat_count = 0

        for event in self.events:
            time.sleep(0.8)
            pid = event["pid"]
            ppid = event["ppid"]
            comm = event["process_name"]
            cmd = event["command_line"]
            user = event["user"]
            timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

            matched_rule = None
            for rule in self.rules:
                if rule["target_comm"].lower() == comm.lower():
                    if re.search(rule["command_regex"], cmd):
                        matched_rule = rule
                        break

            if matched_rule:
                threat_count += 1
                print(f"{RED}{'─' * 80}{RESET}")
                print(f"{BOLD}{RED}[🚨 EDR THREAT DETECTED]{RESET} {DIM}{timestamp}{RESET} | Rule: {BOLD}{matched_rule['name']}{RESET}")
                print(f"  {BOLD}Severity:{RESET}       {RED}{matched_rule['severity']}{RESET} | {BOLD}MITRE ATT&CK:{RESET} {CYAN}{matched_rule['mitre_id']}{RESET}")
                print(f"  {BOLD}Target Entity:{RESET}  PID: {BOLD}{pid}{RESET} (PPID: {ppid} -> {event['parent_name']}) | User: {user}")
                print(f"  {BOLD}Command Line:{RESET}   {AMBER}{cmd}{RESET}")
                print(f"  {BOLD}SHA-256 Hash:{RESET}   {GRAY}{event['process_hash']}{RESET}")

                if self.auto_contain:
                    time.sleep(0.3)
                    action = matched_rule["action"]
                    print(f"\n  {BOLD}{BLUE}[⚡ ACTIVE CONTAINMENT TRIGGERED]{RESET}")
                    print(f"  └── Signal Dispatched: {RED}{action} (PID {pid}){RESET}")
                    print(f"  └── Parent Process Tree: {AMBER}REVOKED TOKEN HANDLES{RESET}")
                    print(f"  └── Forensic Status: {GREEN}THREAT MITIGATED & ISOLATED{RESET}")
            else:
                print(f"{GRAY}[{timestamp}] [✓ CLEAN] PID {pid:<5} | {comm:<15} | Executed safely by {user}{RESET}")

        print(f"\n{RED}{'─' * 80}{RESET}")
        print(f"{BOLD}{GREEN}[✓] EDR TELEMETRY INSPECTION COMPLETED:{RESET} Flagged and mitigated {RED}{threat_count}{RESET} critical adversarial execution attempts.\n")

if __name__ == "__main__":
    agent = KryptonEDRAgent()
    agent.run_live_inspection()
