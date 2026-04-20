import bcrypt
import mysql.connector
from mysql.connector import Error
import os
import time
from dotenv import load_dotenv

# -------------------------
# ATTACK 4 — Pepper Guessing
#
# Scenario: Attacker has the DB dump AND has found the source code
# (e.g. via a public GitHub repo with a hardcoded pepper, or a
# misconfigured server). They now try common pepper values combined
# with a dictionary to crack passwords.
#
# Expected result:
#   If the pepper is guessed correctly → weak passwords crack
#   If the pepper is wrong             → nothing cracks
#   This demonstrates WHY the pepper must be kept secret.
# -------------------------

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))

DB_CONFIG = {
    'host':     os.environ.get("DB_HOST", "localhost"),
    'user':     os.environ.get("DB_USER", "root"),
    'password': os.environ.get("DB_PASSWORD", "root"),
    'database': os.environ.get("DB_NAME", "user_system")
}

# -------------------------
# Common peppers an attacker might try —
# hardcoded values found in public repos, default values, etc.
# -------------------------
PEPPER_GUESSES = [
    "",                         # no pepper at all
    "pepper",
    "secret",
    "pepper123",
    "mysecret",
    "changeme",
    "ch@ng3m3",
    "ch@ng3m3inPr0d!",         # the actual pepper — to show what happens if discovered
    "supersecret",
    "p3pp3r",
    "s3cr3t",
    "defaultpepper",
]

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "qwerty", "abc123",
    "111111", "letmein", "welcome", "admin", "iloveyou",
    "password1", "password123", "passw0rd", "p@ssword",
    "baseball", "football", "soccer", "monkey", "sunshine",
]

def fetch_users() -> list[tuple[int, str, str]]:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, password FROM users")
        users = cursor.fetchall()
        print(f"Found {len(users)} users in database.\n")
        return users
    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

def pepper_guess_attack(users):
    print("=" * 60)
    print("  ATTACK 4 — Pepper Guessing")
    print("=" * 60)

    cracked        = []
    failed         = []
    total_attempts = 0
    start_time     = time.time()

    for userid, username, stored_hash in users:
        found = False

        for pepper_guess in PEPPER_GUESSES:
            if found:
                break

            for word in COMMON_PASSWORDS:
                total_attempts += 1
                candidate = word + pepper_guess

                try:
                    if bcrypt.checkpw(candidate.encode('utf-8'), stored_hash.encode('utf-8')):
                        cracked.append((username, word, pepper_guess))
                        print(f"  [CRACKED] {username:<30} → password: '{word}' pepper: '{pepper_guess}'")
                        found = True
                        break
                except Exception:
                    continue

        if not found:
            failed.append(username)
            print(f"  [FAILED]  {username}")

    elapsed = time.time() - start_time

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Cracked  : {len(cracked)} / {len(users)}")
    print(f"  Failed   : {len(failed)} / {len(users)}")
    print(f"  Attempts : {total_attempts}")
    print(f"  Time     : {elapsed:.2f}s")
    print(f"  Speed    : {total_attempts / elapsed:.1f} attempts/sec" if elapsed > 0 else "  Speed    : N/A")
    print(f"{'=' * 60}")
    print(f"\n  KEY FINDING:")
    print(f"  Passwords only cracked when the correct pepper was")
    print(f"  guessed. This shows that a hardcoded or leaked pepper")
    print(f"  completely breaks the security model. A pepper stored")
    print(f"  in an environment variable and never committed to")
    print(f"  version control prevents this attack entirely.")

if __name__ == "__main__":
    users = fetch_users()
    pepper_guess_attack(users)