import bcrypt
import json
import mysql.connector
from mysql.connector import Error
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
import time

# -------------------------
# CONFIG
# -------------------------
DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'user_system'
}

SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR     = os.path.join(SCRIPT_DIR, "results")

OUTPUT_PATH     = os.path.join(RESULTS_DIR, "a4_cracked.txt")
A1_RESULTS      = os.path.join(RESULTS_DIR, "a1_cracked.txt")
A2_RESULTS      = os.path.join(RESULTS_DIR, "a2_cracked.txt")
A3_RESULTS      = os.path.join(RESULTS_DIR, "a3_cracked.txt")
COMBINED_REPORT = os.path.join(RESULTS_DIR, "combined_report.txt")

# Persistent scoreboard — survives between runs
PEPPER_SCOREBOARD = os.path.join(RESULTS_DIR, "a4_pepper_scoreboard.json")

WORDLIST_PATH   = os.path.join(SCRIPT_DIR, "wordlists", "common_passwords.txt")

# bcrypt releases the GIL so threads give real parallelism
MAX_WORKERS = os.cpu_count() or 4

# Peppers that score 0 across this many consecutive runs get pruned
MAX_DEAD_RUNS = 3

# How many top-scoring peppers to mutate each run
TOP_N_TO_MUTATE = 5

# -------------------------
# ATTACK 4 — Pepper Guessing
#
# Scenario: Attacker has the DB dump AND has found the source code
# (e.g. via a public GitHub repo with a hardcoded pepper, or a
# misconfigured server). They try common pepper values combined
# with a dictionary to crack passwords.
#
# Hash format: bcrypt(plaintext + pepper)   <- mirrors encrypt.py exactly
# Column     : encrypted_password
#
# The pepper list is adaptive — it learns from every run:
#   - Peppers that crack users score points and spawn mutations next run
#   - Peppers that never crack anything accumulate "dead runs"
#   - After MAX_DEAD_RUNS consecutive zeros they are pruned permanently
#   - All historically tried peppers are tracked to avoid re-adding them
# -------------------------

# Seed list — only used on the very first run before any scoreboard exists
INITIAL_PEPPER_GUESSES = [
    "",
    "pepper",
    "secret",
    "pepper123",
    "mysecret",
    "changeme",
    "ch@ng3m3",
    "supersecret",
    "p3pp3r",
    "s3cr3t",
    "defaultpepper",
    "ch@ng3m3inPr0d!",
]


# -------------------------
# PEPPER MUTATION ENGINE
# Applies hashcat-style transformation rules to generate variants
# -------------------------
def mutate(pepper: str) -> list:
    """Generate variants of a pepper using common transformation rules."""
    variants = set()
    p = pepper

    # Capitalisation rules
    variants.add(p.capitalize())
    variants.add(p.upper())
    variants.add(p.lower())
    if p:
        variants.add(p[0].upper() + p[1:].lower())

    # Common suffix appends
    for suffix in ["!", "1", "123", "1!", "2024", "2025", "#", "@", "!1", "01"]:
        variants.add(p + suffix)

    # Common prefix prepends
    for prefix in ["!", "1", "my", "the", "super", "ultra"]:
        variants.add(prefix + p)

    # Leet speak substitution
    leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
    leet = p
    for char, sub in leet_map.items():
        leet = leet.replace(char, sub)
    if leet != p:
        variants.add(leet)
        for suffix in ["!", "1", "123"]:
            variants.add(leet + suffix)

    # Reverse leet (de-obfuscate)
    reverse_leet = {"@": "a", "3": "e", "1": "i", "0": "o", "$": "s", "7": "t"}
    unleet = p
    for char, sub in reverse_leet.items():
        unleet = unleet.replace(char, sub)
    if unleet != p:
        variants.add(unleet)

    # Duplication
    variants.add(p + p)

    # Strip trailing digits/punctuation then re-append common endings
    stripped = p.rstrip("0123456789!@#$%^&*")
    if stripped and stripped != p:
        variants.add(stripped)
        for suffix in ["!", "123", "2024", "2025"]:
            variants.add(stripped + suffix)

    # Remove the source pepper itself — already known
    variants.discard(p)
    variants.discard("")  # blank is already in seeds

    return list(variants)


# -------------------------
# SCOREBOARD  (persisted as JSON between runs)
#
# Schema:
# {
#   "tried": ["pepper1", ...],     <- every pepper ever attempted (no re-adds)
#   "scores": {
#       "pepper1": {
#           "hits":      12,       <- total users cracked with this pepper (all runs)
#           "runs":      4,        <- how many runs this pepper has been tried
#           "dead_runs": 0         <- consecutive runs with 0 hits
#       }
#   }
# }
# -------------------------
def load_scoreboard() -> dict:
    if os.path.exists(PEPPER_SCOREBOARD):
        with open(PEPPER_SCOREBOARD, "r", encoding="utf-8") as f:
            return json.load(f)
    # First-ever run — seed from the initial list
    board = {"tried": list(INITIAL_PEPPER_GUESSES), "scores": {}}
    for p in INITIAL_PEPPER_GUESSES:
        board["scores"][p] = {"hits": 0, "runs": 0, "dead_runs": 0}
    return board


def save_scoreboard(board: dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(PEPPER_SCOREBOARD, "w", encoding="utf-8") as f:
        json.dump(board, f, indent=2)


def build_pepper_list(board: dict) -> list:
    """Return this run's pepper list sorted best-first (most hits first)."""
    scores = board["scores"]

    def sort_key(p):
        s = scores.get(p, {"hits": 0, "dead_runs": 0})
        return (-s["hits"], s["dead_runs"])

    return sorted(scores.keys(), key=sort_key)


def update_scoreboard(board: dict, pepper_hits: dict) -> dict:
    """
    Called after a run. Updates scores, prunes dead peppers,
    and adds mutations of top performers for the next run.

    pepper_hits = {pepper_string: users_cracked_this_run}
    """
    scores = board["scores"]
    tried  = set(board["tried"])

    # Update every pepper that was tried this run
    for pepper, hits in pepper_hits.items():
        if pepper not in scores:
            scores[pepper] = {"hits": 0, "runs": 0, "dead_runs": 0}
        scores[pepper]["hits"]      += hits
        scores[pepper]["runs"]      += 1
        scores[pepper]["dead_runs"]  = (
            0 if hits > 0 else scores[pepper]["dead_runs"] + 1
        )

    # Prune peppers that have been dead for MAX_DEAD_RUNS consecutive runs
    to_prune = [
        p for p, s in scores.items()
        if s["dead_runs"] >= MAX_DEAD_RUNS and s["hits"] == 0
    ]
    for p in to_prune:
        print(f"[PRUNE]   '{p}' — {MAX_DEAD_RUNS} dead runs, no hits ever. Removed.")
        del scores[p]
        tried.add(p)  # remember it so it is never re-added

    # Mutate top performers and queue unseen variants for next run
    top = sorted(
        [(p, s) for p, s in scores.items() if s["hits"] > 0],
        key=lambda x: -x[1]["hits"]
    )[:TOP_N_TO_MUTATE]

    new_peppers = []
    for pepper, _ in top:
        for variant in mutate(pepper):
            if variant not in tried:
                tried.add(variant)
                scores[variant] = {"hits": 0, "runs": 0, "dead_runs": 0}
                new_peppers.append(variant)

    if new_peppers:
        print(f"\n[EVOLVE]  {len(new_peppers)} new mutations queued for next run:")
        for np in new_peppers[:10]:
            print(f"          + '{np}'")
        if len(new_peppers) > 10:
            print(f"          ... and {len(new_peppers) - 10} more")

    board["tried"]  = list(tried)
    board["scores"] = scores
    return board


def print_scoreboard_summary(board: dict):
    scores = board["scores"]
    total  = len(scores)
    hit    = sum(1 for s in scores.values() if s["hits"] > 0)
    dead   = sum(1 for s in scores.values() if s["hits"] == 0 and s["runs"] > 0)
    unseen = sum(1 for s in scores.values() if s["runs"] == 0)

    print(f"\n{'─' * 52}")
    print(f"  Pepper scoreboard  ({total} candidates this run)")
    print(f"  ✓ Hit at least once  : {hit}")
    print(f"  ✗ Tried, no hits     : {dead}")
    print(f"  ○ Queued, not tried  : {unseen}")
    if hit:
        top = sorted(
            [(p, s["hits"]) for p, s in scores.items() if s["hits"] > 0],
            key=lambda x: -x[1]
        )[:5]
        print(f"  Top performers:")
        for p, h in top:
            print(f"    '{p}' -> {h} crack(s)")
    print(f"{'─' * 52}\n")


# -------------------------
# LOAD WORDLIST
# -------------------------
def load_passwords(path):
    if not os.path.exists(path):
        print(f"Wordlist not found: {path}")
        exit(1)

    with open(path, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    passwords = list(set(passwords))
    print(f"Loaded {len(passwords)} unique passwords.\n")
    return passwords


# -------------------------
# LOAD ALREADY CRACKED USERS
# -------------------------
def load_already_cracked(*paths):
    cracked = set()

    for path in paths:
        if not os.path.exists(path):
            continue

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith(("=", "-", "CRACKED", "Username", "No passwords",
                                     "ATTACK", "Date", "Cracked", "Attempts", "Time",
                                     "Charset", "Max", "Speed", "KEY", "•", "Dict",
                                     "Brute", "Total", "bcrypt", "Adding", "COMBINED",
                                     "Generated", "ALL", "Method", "Reason")):
                    continue
                if ":" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    cracked.add(parts[0])

    print(f"Skipping {len(cracked)} already cracked users.\n")
    return cracked


# -------------------------
# FETCH USERS
# -------------------------
def fetch_users(skip):
    try:
        conn   = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT userid, username, encrypted_password FROM users")
        all_users = cursor.fetchall()

        users = [(u, n, h) for u, n, h in all_users if n not in skip]

        print(f"Total users in DB : {len(all_users)}")
        print(f"Already cracked   : {len(all_users) - len(users)}")
        print(f"Attacking         : {len(users)}\n")

        return users

    except Error as e:
        print(f"DB error: {e}")
        exit(1)

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn'   in locals() and conn.is_connected(): conn.close()


# -------------------------
# ATTACK
# -------------------------
def _check_chunk(candidate: bytes, chunk: list) -> list:
    """bcrypt-check a candidate against a user chunk. Returns matched usernames."""
    hits = []
    for _uid, username, stored_hash in chunk:
        if bcrypt.checkpw(candidate, stored_hash):
            hits.append(username)
    return hits


def pepper_guess_attack(users: list, passwords: list, pepper_list: list) -> tuple:
    """
    Returns (results_dict, pepper_hits_dict).
    pepper_hits_dict maps each pepper to how many users it cracked this run.
    """
    cracked = []
    failed  = []

    total_attempts = 0
    start          = time.time()

    # Initialise hit counter for every pepper in this run's list
    pepper_hits = {p: 0 for p in pepper_list}

    # Pre-encode once
    encoded_passwords = [(p, p.encode("utf-8")) for p in passwords]
    user_hashes       = [(u, n, h.encode("utf-8")) for u, n, h in users]

    # O(1) duplicate guard
    cracked_users = set()

    print(f"Running {len(pepper_list)} pepper candidates x {len(passwords)} passwords\n")

    for pepper_guess in pepper_list:
        pepper = pepper_guess.encode("utf-8")

        for plain, plain_enc in encoded_passwords:

            # Shrink active list as users are cracked — less bcrypt work over time
            active = [(uid, un, h) for uid, un, h in user_hashes if un not in cracked_users]
            if not active:
                break   # everyone cracked — stop immediately

            candidate       = plain_enc + pepper
            total_attempts += len(active)

            # Parallel bcrypt — threads actually help because bcrypt releases the GIL
            chunk_size = max(1, len(active) // MAX_WORKERS)
            chunks     = [active[i:i + chunk_size] for i in range(0, len(active), chunk_size)]

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(_check_chunk, candidate, c): c for c in chunks}
                for future in as_completed(futures):
                    for username in future.result():
                        if username not in cracked_users:
                            cracked_users.add(username)
                            cracked.append((username, plain, pepper_guess))
                            pepper_hits[pepper_guess] += 1
                            print(f"[CRACKED] {username:<30} -> '{plain}' | pepper='{pepper_guess}'")
        else:
            continue
        break  # propagate early-exit from inner loop

    for _, username, _ in users:
        if username not in cracked_users:
            failed.append(username)

    elapsed = time.time() - start

    print(f"\nCracked : {len(cracked)} / {len(users)}")
    print(f"Failed  : {len(failed)}")
    print(f"Time    : {elapsed:.4f}s\n")

    results = {
        "cracked":     cracked,
        "failed":      failed,
        "attempts":    total_attempts,
        "time":        elapsed,
        "total_users": len(users),
    }
    return results, pepper_hits


# -------------------------
# SAVE A4 RESULTS
# -------------------------
def save_a4(results: dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("ATTACK 4 — Pepper Guessing\n")
        f.write(f"Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Cracked  : {len(results['cracked'])}\n")
        f.write(f"Attempts : {results['attempts']}\n")
        f.write(f"Time     : {results['time']:.4f}s\n")
        f.write("=" * 60 + "\n\n")

        if results["cracked"]:
            f.write(f"{'Username':<25} {'Password':<20} Pepper Used\n")
            f.write("-" * 60 + "\n")
            for u, p, pepper in results["cracked"]:
                f.write(f"{u:<25} {p:<20} {pepper!r}\n")
        else:
            f.write("No passwords cracked.\n")
            f.write("Reason: Correct pepper was not in the guess list.\n")

    print(f"Saved -> {OUTPUT_PATH}")


# -------------------------
# UPDATE COMBINED REPORT (idempotent)
# -------------------------
def update_combined(results: dict):
    if not os.path.exists(COMBINED_REPORT):
        print("Combined report missing.")
        return

    with open(COMBINED_REPORT, "r", encoding="utf-8") as f:
        report = f.read()

    # 1. Normalise title
    report = re.sub(
        r"(COMBINED ATTACK REPORT — (?:(?!\+ Pepper Guessing).)+?)(\n)",
        lambda m: m.group(1).rstrip() + " + Pepper Guessing" + m.group(2),
        report, count=1
    )

    # 2. Build A4 section
    a4_section = (
        "----------------------------------------------------------------------\n"
        "  ATTACK 4 — Pepper Guessing Summary\n"
        "----------------------------------------------------------------------\n"
        f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Cracked  : {len(results['cracked'])} / {results['total_users']}\n"
        f"  Attempts : {results['attempts']}\n"
        f"  Time     : {results['time']:.4f}s\n"
    )

    # 3. Replace existing block, or insert before ALL CRACKED
    a4_pattern = re.compile(
        r"-{60,}\n  ATTACK 4 — Pepper Guessing Summary\n.*?"
        r"(?=(-{60,}|={60,}))",
        re.DOTALL
    )
    if a4_pattern.search(report):
        report = a4_pattern.sub(a4_section + "\n", report, count=1)
        report = a4_pattern.sub("", report)
    else:
        marker = "=" * 70 + "\n  ALL CRACKED PASSWORDS"
        report = report.replace(marker, a4_section + "\n" + marker)

    # 4. Recompute total attempts
    def recompute_attempts(_m):
        vals = re.findall(r"ATTACK \d.*?Attempts\s*[:\|]\s*([\d,]+)", report, re.DOTALL)
        total = sum(int(v.replace(",", "")) for v in vals)
        return f"  Total Attempts: {total:,}"

    report = re.sub(r"  Total Attempts: [\d,]+", recompute_attempts, report)

    # 5. KEY FINDINGS bullet — exactly once
    bullet = (
        "  • Pepper guessing cracked accounts only when the correct pepper was found"
        " — a leaked pepper breaks the security model entirely."
    )
    report = report.replace(bullet + "\n", "").replace(bullet, "")
    report = re.sub(r"(KEY FINDINGS\n)", r"\1" + bullet + "\n", report, count=1)

    with open(COMBINED_REPORT, "w", encoding="utf-8") as f:
        f.write(report)

    print("Updated combined report.\n")


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    passwords = load_passwords(WORDLIST_PATH)
    skip      = load_already_cracked(A1_RESULTS, A2_RESULTS, A3_RESULTS)
    users     = fetch_users(skip)

    # Load (or initialise) the adaptive scoreboard
    board       = load_scoreboard()
    pepper_list = build_pepper_list(board)

    print_scoreboard_summary(board)

    # Run the attack
    results, pepper_hits = pepper_guess_attack(users, passwords, pepper_list)

    # Evolve the scoreboard — prune dead peppers, queue mutations of winners
    board = update_scoreboard(board, pepper_hits)
    save_scoreboard(board)

    save_a4(results)
    update_combined(results)