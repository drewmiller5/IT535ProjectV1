import bcrypt
import mysql.connector
from mysql.connector import Error
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

OUTPUT_PATH     = os.path.join(RESULTS_DIR, "a5_cracked.txt")
COMBINED_REPORT = os.path.join(RESULTS_DIR, "combined_report.txt")

BREACHES_PATH   = os.path.join(SCRIPT_DIR, "wordlists", "known_breaches.txt")


# -------------------------
# LOAD BREACH LIST
# -------------------------
def load_breach_list(path: str) -> list[tuple[str, str]]:
    if not os.path.exists(path):
        print(f"❌ Breach list not found at: {path}")
        exit(1)

    pairs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and ":" in line and not line.startswith("#"):
                username, password = line.split(":", 1)
                pairs.append((username.strip(), password.strip()))

    print(f"Loaded {len(pairs)} credential pairs.\n")
    return pairs


# -------------------------
# FETCH USERS
# -------------------------
def fetch_users() -> dict[str, tuple[int, str]]:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # IMPORTANT: must match hashed column used in encryption stage
        cursor.execute("SELECT userid, username, encrypted_password FROM users")
        rows = cursor.fetchall()

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
# ATTACK 5 — Credential Stuffing
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
            print(f"[NO USER] {username:<30}")
            continue

        userid, stored_hash = users[username]

        try:
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                cracked.append((username, password))
                print(f"[CRACKED] {username:<30} → {password}")
            else:
                failed.append(username)
                print(f"[FAILED]  {username:<30}")
        except Exception:
            failed.append(username)

    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Cracked   : {len(cracked)}")
    print(f"Failed    : {len(failed)}")
    print(f"Not found : {len(not_found)}")
    print(f"Attempts  : {total_attempts}")
    print(f"Time      : {elapsed:.2f}s")
    print("=" * 60)

    return {
        "cracked": cracked,
        "failed": failed,
        "not_found": not_found,
        "attempts": total_attempts,
        "time": elapsed,
        "total_users": len(users)
    }


# -------------------------
# SAVE A5 RESULTS
# -------------------------
def save_a5(results):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("ATTACK 5 — Credential Stuffing\n")
        f.write(f"Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Cracked  : {len(results['cracked'])}\n")
        f.write(f"Attempts : {results['attempts']}\n")
        f.write(f"Time     : {results['time']:.4f}s\n")
        f.write("=" * 60 + "\n\n")

        if results["cracked"]:
            f.write(f"{'Username':<25} Password\n")
            f.write("-" * 50 + "\n")
            for u, p in results["cracked"]:
                f.write(f"{u:<25} {p}\n")
        else:
            f.write("No passwords cracked.\n")
            f.write("Reason: No reused credentials in breach list.\n")

    print(f"Saved → {OUTPUT_PATH}")


# -------------------------
# UPDATE COMBINED REPORT
# -------------------------
def update_combined(results):
    if not os.path.exists(COMBINED_REPORT):
        print("⚠️ Combined report missing.")
        return

    with open(COMBINED_REPORT, "r", encoding="utf-8") as f:
        report = f.read()

    # Add attack section if not already present
    if "Credential Stuffing" not in report:
        insert = (
            "----------------------------------------------------------------------\n"
            "  ATTACK 5 — Credential Stuffing Summary\n"
            "----------------------------------------------------------------------\n"
            f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Cracked  : {len(results['cracked'])} / {results['total_users']}\n"
            f"  Attempts : {results['attempts']}\n"
            f"  Time     : {results['time']:.4f}s\n\n"
        )

        report = report.replace("ALL CRACKED PASSWORDS", insert + "ALL CRACKED PASSWORDS")

    # recompute total attempts
    def recompute(_m):
        vals = re.findall(r"ATTACK \d.*?Attempts\s*[:\|]\s*([\d,]+)", report, re.DOTALL)
        total = sum(int(v.replace(",", "")) for v in vals)
        return f"  Total Attempts: {total:,}"

    report = re.sub(r"  Total Attempts: [\d,]+", recompute, report)

    # key finding injection
    bullet = "  • Credential stuffing exploits password reuse across services."
    if bullet not in report:
        report = report.replace("KEY FINDINGS", "KEY FINDINGS\n" + bullet)

    with open(COMBINED_REPORT, "w", encoding="utf-8") as f:
        f.write(report)

    print("Updated combined report.")


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    breach_list = load_breach_list(BREACHES_PATH)
    users       = fetch_users()

    results = credential_stuffing_attack(users, breach_list)

    save_a5(results)
    update_combined(results)