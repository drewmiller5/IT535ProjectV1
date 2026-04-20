import bcrypt
import mysql.connector
from mysql.connector import Error
import os
import time
from dotenv import load_dotenv

# -------------------------
# ATTACK 3 — Rainbow Table
#
# Scenario: Attacker has a precomputed table of password → hash
# mappings and looks up hashes directly instead of computing them.
# This is devastating against MD5/SHA-1 but bcrypt's per-user salt
# makes rainbow tables completely useless.
#
# Expected result:
#   0 passwords cracked — every lookup will fail.
#   This attack exists to DEMONSTRATE bcrypt's salt working.
# -------------------------

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))

DB_CONFIG = {
    'host':     os.environ.get("DB_HOST", "localhost"),
    'user':     os.environ.get("DB_USER", "root"),
    'password': os.environ.get("DB_PASSWORD", "root"),
    'database': os.environ.get("DB_NAME", "user_system")
}

# -------------------------
# Simulated rainbow table
# In a real attack this would be a massive precomputed file.
# We simulate it by precomputing hashes WITHOUT a unique salt —
# exactly how MD5/SHA-1 rainbow tables work.
# -------------------------
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "master",
    "sunshine", "princess", "shadow", "superman", "iloveyou",
    "password1", "password123", "passw0rd", "p@ssword",
    "baseball", "football", "soccer", "basketball",
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

def build_rainbow_table(passwords: list[str]) -> dict:
    """
    Simulates a precomputed rainbow table using a FIXED salt —
    exactly how unsalted MD5/SHA-1 tables work.
    bcrypt requires a salt so we use a single fixed one to simulate
    what an attacker would precompute.
    """
    print("Building simulated rainbow table (fixed salt)...")
    fixed_salt = bcrypt.gensalt(rounds=4)  # low rounds for speed in demo
    table = {}
    for pwd in passwords:
        h = bcrypt.hashpw(pwd.encode('utf-8'), fixed_salt).decode('utf-8')
        table[h] = pwd
    print(f"Rainbow table built with {len(table)} entries.\n")
    return table

def rainbow_table_attack(users, rainbow_table):
    print("=" * 60)
    print("  ATTACK 3 — Rainbow Table Lookup")
    print("=" * 60)

    cracked        = []
    failed         = []
    total_attempts = 0
    start_time     = time.time()

    for userid, username, stored_hash in users:
        total_attempts += 1

        # Direct lookup — no computation needed, just a table lookup
        if stored_hash in rainbow_table:
            password = rainbow_table[stored_hash]
            cracked.append((username, password))
            print(f"  [CRACKED] {username:<30} → {password}")
        else:
            failed.append(username)
            print(f"  [FAILED]  {username} — hash not in table")

    elapsed = time.time() - start_time

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Cracked  : {len(cracked)} / {len(users)}")
    print(f"  Failed   : {len(failed)} / {len(users)}")
    print(f"  Attempts : {total_attempts}")
    print(f"  Time     : {elapsed:.4f}s")
    print(f"{'=' * 60}")
    print(f"\n  WHY THIS FAILED:")
    print(f"  bcrypt embeds a unique random salt in every hash.")
    print(f"  Even if two users have the same password, their")
    print(f"  hashes are completely different — a precomputed")
    print(f"  table can never match them. Rainbow tables are")
    print(f"  entirely defeated by per-user salting.")

if __name__ == "__main__":
    users         = fetch_users()
    rainbow_table = build_rainbow_table(COMMON_PASSWORDS)
    rainbow_table_attack(users, rainbow_table)