import bcrypt
import mysql.connector
from mysql.connector import Error
import os
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

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR      = os.path.join(SCRIPT_DIR, "results")

OUTPUT_PATH      = os.path.join(RESULTS_DIR, "a3_cracked.txt")
A1_RESULTS       = os.path.join(RESULTS_DIR, "a1_cracked.txt")
A2_RESULTS       = os.path.join(RESULTS_DIR, "a2_cracked.txt")
COMBINED_REPORT  = os.path.join(RESULTS_DIR, "combined_report.txt")

WORDLIST_PATH    = os.path.join(SCRIPT_DIR, "wordlists", "common_passwords.txt")


# -------------------------
# LOAD WORDLIST
# -------------------------
def load_passwords(path):
    if not os.path.exists(path):
        print(f"❌ Wordlist not found: {path}")
        exit(1)

    with open(path, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    passwords = list(set(passwords))

    print(f"Loaded {len(passwords)} unique passwords.\n")
    return passwords


# -------------------------
# LOAD ALREADY CRACKED USERS
# Fix: parse the 3-column format used in a1/a2 results:
#   "username   password   Method"
# and also handle plain 2-column "username password" lines.
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

                # Skip headers, separators, and metadata lines
                if line.startswith(("=", "-", "CRACKED", "Username", "No passwords",
                                     "ATTACK", "Date", "Cracked", "Attempts", "Time",
                                     "Charset", "Max", "Speed", "KEY", "•", "Dict",
                                     "Brute", "Total", "bcrypt", "Adding", "COMBINED",
                                     "Generated", "ALL", "Method")):
                    continue

                # Skip lines that contain colons (metadata like "Date : ...")
                if ":" in line:
                    continue

                parts = line.split()

                # Accept lines with 2 or 3 parts: "username password [method]"
                if len(parts) >= 2:
                    username = parts[0]
                    cracked.add(username)

    print(f"Skipping {len(cracked)} already cracked users.\n")
    return cracked


# -------------------------
# FETCH USERS
# -------------------------
def fetch_users(skip):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT userid, username, encrypted_nopep FROM users")
        all_users = cursor.fetchall()

        users = [(u, n, h) for u, n, h in all_users if n not in skip]

        print(f"Total users: {len(all_users)}")
        print(f"Attacking  : {len(users)}\n")

        return users

    except Error as e:
        print(f"❌ DB error: {e}")
        exit(1)

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()


# -------------------------
# BUILD RAINBOW TABLE
# -------------------------
def build_rainbow_table(passwords):
    print("Building rainbow table (fixed salt)...")

    fixed_salt = bcrypt.gensalt(rounds=4)
    table = {}

    for pwd in passwords:
        h = bcrypt.hashpw(pwd.encode(), fixed_salt).decode()
        table[h] = pwd

    print(f"Built {len(table)} entries.\n")
    return table


# -------------------------
# ATTACK
# -------------------------
def rainbow_table_attack(users, table):
    cracked = []
    failed = []

    attempts = 0
    start = time.time()

    for _, username, stored_hash in users:
        attempts += 1

        if stored_hash in table:
            password = table[stored_hash]
            cracked.append((username, password))
            print(f"[CRACKED] {username} → {password}")
        else:
            failed.append(username)

    elapsed = time.time() - start

    print(f"\nCracked: {len(cracked)} / {len(users)}")
    print(f"Time   : {elapsed:.4f}s\n")

    return {
        "cracked": cracked,
        "failed": failed,
        "attempts": attempts,
        "time": elapsed,
        "total_users": len(users)
    }


# -------------------------
# SAVE A3 RESULTS
# -------------------------
def save_a3(results):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("ATTACK 3 — Rainbow Table\n")
        f.write(f"Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Cracked  : {len(results['cracked'])}\n")
        f.write(f"Attempts : {results['attempts']}\n")
        f.write(f"Time     : {results['time']:.4f}s\n")
        f.write("=" * 60 + "\n\n")

        if results["cracked"]:
            for u, p in results["cracked"]:
                f.write(f"{u:<25} {p}\n")
        else:
            f.write("No passwords cracked.\n")
            f.write("Reason: bcrypt uses per-user salts, making rainbow tables ineffective.\n")

    print(f"Saved → {OUTPUT_PATH}")


# -------------------------
# UPDATE COMBINED REPORT (idempotent)
# Replaces the existing Attack 3 section if present, or inserts it.
# Avoids duplicate titles, sections, and bullet points.
# -------------------------
def update_combined(results):
    if not os.path.exists(COMBINED_REPORT):
        print("⚠️ Combined report missing.")
        return

    with open(COMBINED_REPORT, "r", encoding="utf-8") as f:
        report = f.read()

    # ── 1. Normalise the title to the canonical final form (idempotent) ──
    import re
    # Strip any existing "+ Rainbow Table" suffixes, then add exactly one
    title_base = "Dictionary + Brute Force"
    # Remove all existing rainbow-table suffixes
    report = re.sub(
        r"(Dictionary \+ Brute Force)( \+ Rainbow Table)*",
        r"\1 + Rainbow Table",
        report
    )

    # ── 2. Build the new Attack 3 section ──
    a3_section = (
        "----------------------------------------------------------------------\n"
        "  ATTACK 3 — Rainbow Table Summary\n"
        "----------------------------------------------------------------------\n"
        f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Cracked  : {len(results['cracked'])} / {results['total_users']}\n"
        f"  Attempts : {results['attempts']}\n"
        f"  Time     : {results['time']:.4f}s\n"
    )

    # ── 3. Replace existing Attack 3 block, or insert before the ALL CRACKED section ──
    a3_pattern = re.compile(
        r"-{60,}\n  ATTACK 3 — Rainbow Table Summary\n.*?"
        r"(?=(-{60,}|={60,}))",   # stop at next section divider
        re.DOTALL
    )

    if a3_pattern.search(report):
        # Replace the existing (possibly duplicated) block with a single fresh one
        report = a3_pattern.sub(a3_section + "\n", report, count=1)
        # Remove any further duplicate Attack 3 blocks
        report = a3_pattern.sub("", report)
    else:
        # Insert before the ALL CRACKED section
        marker = "=" * 70 + "\n  ALL CRACKED PASSWORDS"
        report = report.replace(marker, a3_section + "\n" + marker)

    # ── 4. Update Total Attempts (replace old value) ──
    def replace_total_attempts(m):
        vals = re.findall(r"Attempts\s*[:\|]\s*([\d,]+)", report)
        total = sum(int(v.replace(",", "")) for v in vals)
        return f"  Total Attempts: {total:,}"

    report = re.sub(r"  Total Attempts: [\d,]+", replace_total_attempts, report)

    # ── 5. Ensure the KEY FINDINGS bullet appears exactly once ──
    bullet = "  • Rainbow table attack cracked 0 accounts due to bcrypt salting."
    # Remove all existing occurrences
    report = report.replace(bullet + "\n", "")
    report = report.replace(bullet, "")
    # Insert once after "KEY FINDINGS"
    report = report.replace(
        "KEY FINDINGS",
        "KEY FINDINGS\n" + bullet,
        1   # only the first occurrence
    )

    with open(COMBINED_REPORT, "w", encoding="utf-8") as f:
        f.write(report)

    print("Updated combined report.\n")


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    passwords = load_passwords(WORDLIST_PATH)
    skip      = load_already_cracked(A1_RESULTS, A2_RESULTS)

    users     = fetch_users(skip)
    table     = build_rainbow_table(passwords)

    results   = rainbow_table_attack(users, table)

    save_a3(results)
    update_combined(results)