import bcrypt
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

MAX_WORKERS = os.cpu_count() or 4

OUTPUT_PATH     = os.path.join(RESULTS_DIR, "a4_cracked.txt")
A1_RESULTS      = os.path.join(RESULTS_DIR, "a1_cracked.txt")
A2_RESULTS      = os.path.join(RESULTS_DIR, "a2_cracked.txt")
A3_RESULTS      = os.path.join(RESULTS_DIR, "a3_cracked.txt")
COMBINED_REPORT = os.path.join(RESULTS_DIR, "combined_report.txt")

WORDLIST_PATH   = os.path.join(SCRIPT_DIR, "wordlists", "common_passwords.txt")

# -------------------------
# ATTACK 4 — Pepper Guessing
#
# Scenario: Attacker has the DB dump AND has found the source code
# (e.g. via a public GitHub repo with a hardcoded pepper, or a
# misconfigured server). They try common pepper values combined
# with a dictionary to crack peppered hashes.
#
# Hash format : bcrypt(plaintext + pepper)  ← mirrors encrypt.py exactly
# Column      : encrypted_password
#
# Expected result:
#   Wrong peppers  → nothing cracks (demonstrates pepper protection)
#   Correct pepper → weak passwords crack (demonstrates why secrecy matters)
# -------------------------

PEPPER_GUESSES = [
    "",                     # no pepper — baseline test
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
    "ch@ng3m3inPr0d!",      # actual pepper — simulates source code / repo leak
]


# -------------------------
# LOAD WORDLIST
# Skips comment lines starting with #
# -------------------------
def load_passwords(path):
    if not os.path.exists(path):
        print(f"❌ Wordlist not found: {path}")
        exit(1)

    with open(path, "r", encoding="utf-8") as f:
        passwords = [
            line.strip() for line in f
            if line.strip() and not line.startswith("#")
        ]

    passwords = list(dict.fromkeys(passwords))  # dedupe, preserve order
    print(f"Loaded {len(passwords)} unique passwords.\n")
    return passwords


# -------------------------
# LOAD ALREADY CRACKED USERS
# Handles the result file format used by A1–A3:
#   "username   password   [Method]"
# and A4's own 3-column format:
#   "username   password   'pepper'"
# -------------------------
def load_already_cracked(*paths):
    cracked = set()

    skip_prefixes = (
        "=", "-", "CRACKED", "Username", "No ", "ATTACK", "Date", "Cracked",
        "Attempts", "Time", "Charset", "Max", "Speed", "KEY", "•",
        "Total", "bcrypt", "Adding", "COMBINED", "Generated", "ALL",
        "Method", "Reason", "Pepper", "Failed", "Note",
    )

    for path in paths:
        if not os.path.exists(path):
            continue

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith(skip_prefixes):
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
# Fetches ALL users with encrypted_password
# Known cracked users are kept as anchors for pepper verification
# -------------------------
def fetch_users(skip):
    try:
        conn   = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT userid, username, encrypted_password FROM users")
        all_users = cursor.fetchall()

        # Keep ALL users — skip set is used separately in attack loop
        users = [(u, n, h) for u, n, h in all_users if h]

        print(f"Total users: {len(all_users)}")
        print(f"Attacking  : {len(users)} (includes known cracked as pepper anchors)\n")

        return users

    except Error as e:
        print(f"❌ DB error: {e}")
        exit(1)

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn'   in locals() and conn.is_connected(): conn.close()



# -------------------------
# THREADED BCRYPT HELPER
# -------------------------
def _check_chunk(candidate: bytes, chunk: list) -> list:
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
# Outer loop: pepper guesses (cheap — just string concat)
# Inner loop: wordlist × users
#
# We go pepper-outer so we can report clearly which pepper cracked
# each account — important for the research narrative.
# -------------------------
def pepper_guess_attack(users, passwords, already_cracked, known_pairs):
    total_attempts = 0
    found_pepper   = None
    start          = time.time()

    # Build lookup of username -> hash for all users
    hash_lookup = {n: h for _, n, h in users}

    print("=" * 60)
    print("  PHASE 1 — Pepper Discovery")
    print(f"  Testing {len(PEPPER_GUESSES)} peppers against {len(known_pairs)} known pairs")
    print("=" * 60)

    for pepper_guess in PEPPER_GUESSES:
        print(f"  Trying pepper: '{pepper_guess}'")

        for username, plaintext in known_pairs.items():
            if username not in hash_lookup:
                continue

            stored_hash    = hash_lookup[username]
            candidate      = (plaintext + pepper_guess).encode("utf-8")
            total_attempts += 1

            try:
                if bcrypt.checkpw(candidate, stored_hash.encode("utf-8")):
                    found_pepper = pepper_guess
                    print(f"\n  ✅ PEPPER FOUND: '{pepper_guess}'")
                    print(f"     Confirmed via : {username} → '{plaintext}'")
                    print(f"     Run A6 to exploit this pepper against all users.\n")
                    break
            except Exception:
                continue

        if found_pepper is not None:
            break

    elapsed = time.time() - start

    if found_pepper is None:
        print("\n  ❌ Pepper not found in guess list.")
        print("     Add more pepper candidates to PEPPER_GUESSES and retry.\n")

    print(f"{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Pepper found : {repr(found_pepper) if found_pepper else 'Not found'}")
    print(f"  Attempts     : {total_attempts:,}")
    print(f"  Time         : {elapsed:.2f}s")
    print(f"{'=' * 60}")

    return {
        "cracked":      [],
        "failed":       [],
        "attempts":     total_attempts,
        "time":         elapsed,
        "total_users":  len(users),
        "found_pepper": found_pepper,
    }


# -------------------------
# SAVE A4 RESULTS
# NOTE: "Pepper   : '...'" line is machine-readable — A6 loads it.
# Do not change that line's format.
# -------------------------
def save_a4(results):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    pepper_val = results["found_pepper"]
    pepper_str = repr(pepper_val) if pepper_val is not None else "Not found"

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("ATTACK 4 — Pepper Guessing\n")
        f.write(f"Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Pepper   : {pepper_str}\n")          # ← A6 reads this line
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
            if pepper_val is not None:
                f.write(f"Reason: Pepper {pepper_str} found but no passwords matched wordlist.\n")
            else:
                f.write("Reason: Correct pepper was not in the guess list.\n")

    print(f"Saved → {OUTPUT_PATH}")


# -------------------------
# UPDATE COMBINED REPORT (idempotent)
# -------------------------
def update_combined(results):
    if not os.path.exists(COMBINED_REPORT):
        print("⚠️ Combined report missing.")
        return

    with open(COMBINED_REPORT, "r", encoding="utf-8") as f:
        report = f.read()

    # ── 1. Normalise title — append "+ Pepper Guessing" exactly once ──
    report = re.sub(
        r"(COMBINED ATTACK REPORT — (?:(?!\+ Pepper Guessing).)+?)(\n)",
        lambda m: m.group(1).rstrip() + " + Pepper Guessing" + m.group(2),
        report,
        count=1
    )

    # ── 2. Build the Attack 4 section ──
    pepper_str = repr(results["found_pepper"]) if results["found_pepper"] else "Not found"
    a4_section = (
        "----------------------------------------------------------------------\n"
        "  ATTACK 4 — Pepper Guessing Summary\n"
        "----------------------------------------------------------------------\n"
        f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Pepper   : {pepper_str}\n"
        f"  Cracked  : {len(results['cracked'])} / {results['total_users']}\n"
        f"  Attempts : {results['attempts']}\n"
        f"  Time     : {results['time']:.4f}s\n"
    )

    # ── 3. Replace existing A4 block or insert before ALL CRACKED ──
    a4_pattern = re.compile(
        r"-{60,}\n  ATTACK 4 — Pepper Guessing Summary\n.*?(?=(-{60,}|={60,}))",
        re.DOTALL
    )
    if a4_pattern.search(report):
        report = a4_pattern.sub(a4_section + "\n", report, count=1)
        report = a4_pattern.sub("", report)
    else:
        marker = "=" * 70 + "\n  ALL CRACKED PASSWORDS"
        report = report.replace(marker, a4_section + "\n" + marker)

    # ── 4. Append newly cracked users to ALL CRACKED table ──
    if results["cracked"]:
        existing = set(re.findall(
            r"^\s{2}(\S+)\s+\S+\s+\w", report, re.MULTILINE
        ))
        new_rows = ""
        for u, p, _pepper in results["cracked"]:
            if u not in existing:
                new_rows += f"  {u:<33} {p:<20} Pepper Guess (A4)\n"
        if new_rows:
            report = re.sub(
                r"(\n={70,}\n  KEY FINDINGS)",
                "\n" + new_rows + r"\1",
                report
            )
        # Update Total Cracked
        match = re.search(r"Total Cracked\s*:\s*(\d+)", report)
        if match:
            new_total = int(match.group(1)) + len(results["cracked"])
            report = re.sub(
                r"Total Cracked\s*:\s*\d+",
                f"Total Cracked : {new_total}",
                report
            )

    # ── 5. Recompute Total Attempts ──
    def recompute_attempts(_m):
        vals = re.findall(r"Attempts\s*[:\|]\s*([\d,]+)", report)
        total = sum(int(v.replace(",", "")) for v in vals)
        return f"  Total Attempts: {total:,}"

    report = re.sub(r"  Total Attempts: [\d,]+", recompute_attempts, report)

    # ── 6. KEY FINDINGS bullet — exactly once ──
    bullet = "  • Pepper guessing cracked accounts only when the correct pepper was found — a leaked pepper breaks the security model entirely."
    report = report.replace(bullet + "\n", "").replace(bullet, "")
    report = re.sub(r"(KEY FINDINGS\n)", r"\1" + bullet + "\n", report, count=1)

    with open(COMBINED_REPORT, "w", encoding="utf-8") as f:
        f.write(report)

    print("Updated combined report.\n")


# -------------------------
# MAIN
# -------------------------
# -------------------------
# LOAD KNOWN PLAINTEXT PAIRS FROM A1-A3
# Returns dict of username -> plaintext password
# -------------------------
def load_cracked_pairs(*paths) -> dict:
    pairs = {}
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
                if not in_cracked_section:
                    continue
                if not line or line.startswith(("-", "Username", "=")):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] not in pairs:
                    pairs[parts[0]] = parts[1]
    print(f"  Loaded {len(pairs)} known plaintext pairs from previous attacks:")
    for u, p in pairs.items():
        print(f"    {u:<30} → '{p}'")
    print()
    return pairs


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    passwords    = load_passwords(WORDLIST_PATH)
    skip         = load_already_cracked(A1_RESULTS, A2_RESULTS, A3_RESULTS)
    known_pairs  = load_cracked_pairs(A1_RESULTS, A2_RESULTS, A3_RESULTS)
    users        = fetch_users(skip)

    if not known_pairs:
        print("❌ No known plaintext passwords — run A1-A3 first.")
        exit(1)

    results = pepper_guess_attack(users, passwords, skip, known_pairs)
    print(f"DEBUG — found_pepper : {results['found_pepper']}")
    print(f"DEBUG — cracked count: {len(results['cracked'])}")
    save_a4(results)
    update_combined(results)