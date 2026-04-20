import bcrypt
import mysql.connector
from mysql.connector import Error
import os
import time

# -------------------------
# ATTACK 1 — Dictionary Attack
#
# Scenario: Attacker has stolen the database dump.
# They have usernames and bcrypt hashes but NOT the pepper.
# They try every password in a common wordlist against every hash.
#
# Targets: encrypted_nopep column (bcrypt, no pepper)
#
# Expected result:
#   Weak passwords (abc123, password, qwerty) → CRACKED instantly
#   Medium/Strong passwords                   → FAILED
# -------------------------

DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'user_system'
    # 'port': 8889
}

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "wordlists", "common_passwords.txt")
OUTPUT_PATH   = os.path.join(SCRIPT_DIR, "results", "a1_cracked.txt")

def load_wordlist(path: str) -> list[str]:
    if not os.path.exists(path):
        print(f"❌ Wordlist not found at: {path}")
        exit(1)

    words = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)

    print(f"Loaded {len(words)} passwords from wordlist.")
    return words

def fetch_users() -> list[tuple[int, str, str]]:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, encrypted_nopep FROM users")
        users = cursor.fetchall()
        print(f"Found {len(users)} users in database.\n")
        return users
    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

def save_results(cracked: list[tuple[str, str]], elapsed: float, total_attempts: int, total_users: int):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  ATTACK 1 — Dictionary Attack Results\n")
        f.write(f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Cracked  : {len(cracked)} / {total_users}\n")
        f.write(f"  Attempts : {total_attempts}\n")
        f.write(f"  Time     : {elapsed:.2f}s\n")
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

def dictionary_attack(users, wordlist):
    print("=" * 60)
    print("  ATTACK 1 — Dictionary Attack")
    print("  Target: bcrypt hashes WITHOUT pepper")
    print("=" * 60)

    cracked        = []
    failed         = []
    total_attempts = 0
    start_time     = time.time()

    for userid, username, stored_hash in users:
        found = False

        for word in wordlist:
            total_attempts += 1
            try:
                if bcrypt.checkpw(word.encode('utf-8'), stored_hash.encode('utf-8')):
                    cracked.append((username, word))
                    print(f"  [CRACKED] {username:<30} → {word}")
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

    if cracked:
        print(f"\n  ⚠️  Cracked passwords:")
        for username, password in cracked:
            print(f"     {username:<30} {password}")

    print(f"\n  KEY FINDING:")
    print(f"  bcrypt alone is not enough — weak passwords")
    print(f"  are cracked instantly with a dictionary attack.")
    print(f"  Run attack 4 to see how pepper stops this.")

    save_results(cracked, elapsed, total_attempts, len(users))

if __name__ == "__main__":
    wordlist = load_wordlist(WORDLIST_PATH)
    users    = fetch_users()
    dictionary_attack(users, wordlist)