import bcrypt
import mysql.connector
from mysql.connector import Error
import os
import time
import itertools
import string

# -------------------------
# ATTACK 2 — Brute Force
#
# Scenario: Attacker tries every possible character combination
# up to a max length. No wordlist, no pepper.
# Skips users already cracked by Attack 1.
#
# Expected result:
#   Very short passwords (1-4 chars) MAY crack
#   Anything longer is practically uncrackable this way
#   This attack demonstrates WHY bcrypt's cost factor matters
# -------------------------

DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'user_system'
    # 'port': 8889
}

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PATH   = os.path.join(SCRIPT_DIR, "results", "a2_cracked.txt")
A1_RESULTS    = os.path.join(SCRIPT_DIR, "results", "a1_cracked.txt")

# Keep MAX_LENGTH at 4-5 or this runs for hours
CHARSET    = string.ascii_lowercase + string.digits
MAX_LENGTH = 4

# -------------------------
# Load already cracked usernames from Attack 1
# so we don't waste time on them
# -------------------------
def load_already_cracked(path: str) -> set[str]:
    cracked = set()
    if not os.path.exists(path):
        print("  No Attack 1 results found — attacking all users.")
        return cracked

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Lines look like: "username                       password"
            if line and not line.startswith("=") and not line.startswith("-") and not line.startswith("CRACKED") and not line.startswith("Username") and not line.startswith("Date") and not line.startswith("Cracked") and not line.startswith("Attempts") and not line.startswith("Time") and not line.startswith("Attack") and not line.startswith("No"):
                parts = line.split()
                if parts:
                    cracked.add(parts[0])

    print(f"  Skipping {len(cracked)} users already cracked by Attack 1.")
    return cracked

def fetch_users(skip: set[str]) -> list[tuple[int, str, str]]:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, encrypted_nopep FROM users")
        all_users = cursor.fetchall()

        # Filter out already cracked users
        users = [(uid, uname, uhash) for uid, uname, uhash in all_users if uname not in skip]
        print(f"Found {len(all_users)} users — attacking {len(users)} (skipping {len(skip)} already cracked).\n")
        return users
    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

def save_results(cracked, elapsed, total_attempts, total_users, speed):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  ATTACK 2 — Brute Force Results\n")
        f.write(f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Charset  : {CHARSET}\n")
        f.write(f"  Max Len  : {MAX_LENGTH}\n")
        f.write(f"  Cracked  : {len(cracked)} / {total_users}\n")
        f.write(f"  Attempts : {total_attempts}\n")
        f.write(f"  Time     : {elapsed:.2f}s\n")
        f.write(f"  Speed    : {speed:.1f} attempts/sec\n")
        f.write("=" * 60 + "\n\n")

        if cracked:
            f.write("CRACKED PASSWORDS:\n")
            f.write(f"{'Username':<30} {'Password'}\n")
            f.write("-" * 50 + "\n")
            for username, password in cracked:
                f.write(f"{username:<30} {password}\n")
        else:
            f.write("No passwords cracked.\n")

    print(f"\n✅ Results saved to: {OUTPUT_PATH}")

def brute_force_attack(users):
    print("=" * 60)
    print(f"  ATTACK 2 — Brute Force")
    print(f"  Target    : bcrypt hashes WITHOUT pepper")
    print(f"  Charset   : {CHARSET}")
    print(f"  Max length: {MAX_LENGTH}")
    print("=" * 60)

    cracked        = []
    failed         = []
    total_attempts = 0
    start_time     = time.time()

    for userid, username, stored_hash in users:
        found      = False
        user_start = time.time()

        print(f"  Attacking {username}...")

        for length in range(1, MAX_LENGTH + 1):
            if found:
                break
            for combo in itertools.product(CHARSET, repeat=length):
                guess = ''.join(combo)
                total_attempts += 1

                try:
                    if bcrypt.checkpw(guess.encode('utf-8'), stored_hash.encode('utf-8')):
                        elapsed_user = time.time() - user_start
                        cracked.append((username, guess))
                        print(f"  [CRACKED] {username:<30} → {guess} ({elapsed_user:.2f}s)")
                        found = True
                        break
                except Exception:
                    continue

        if not found:
            failed.append(username)
            print(f"  [FAILED]  {username} — not found within length {MAX_LENGTH}")

    elapsed = time.time() - start_time
    speed   = total_attempts / elapsed if elapsed > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Cracked  : {len(cracked)} / {len(users)}")
    print(f"  Failed   : {len(failed)} / {len(users)}")
    print(f"  Attempts : {total_attempts}")
    print(f"  Time     : {elapsed:.2f}s")
    print(f"  Speed    : {speed:.1f} attempts/sec")
    print(f"{'=' * 60}")
    print(f"\n  NOTE: bcrypt cost 6 (demo) = ~{speed:.0f} guesses/sec")
    print(f"  bcrypt cost 12 (production) = ~4 guesses/sec")
    print(f"  An 8-char password has {len(CHARSET)**8:,} combinations")
    if speed > 0:
        years = len(CHARSET)**8 / speed / 3600 / 24 / 365
        print(f"  At cost 12 that would take {years:.0f}+ years to crack")

    save_results(cracked, elapsed, total_attempts, len(users), speed)

if __name__ == "__main__":
    already_cracked = load_already_cracked(A1_RESULTS)
    users           = fetch_users(already_cracked)
    brute_force_attack(users)