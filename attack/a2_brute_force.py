import bcrypt
import mysql.connector
from mysql.connector import Error
import os
import time
import itertools
import string

# -------------------------
# ATTACK 2 — Brute Force
# + Combined Report Generator
#
# Scenario: Attacker tries every possible character combination
# up to a max length. No wordlist, no pepper.
# Skips users already cracked by Attack 1.
#
# IMPROVEMENT: Breadth-first approach — tries all users at length 1,
# then all users at length 2, etc. This means short passwords are
# found faster instead of burning time per user one at a time.
#
# Expected result:
#   Very short passwords (1-3 chars) MAY crack
#   Anything longer hits the time limit and moves on
#   This demonstrates WHY bcrypt's cost factor matters
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
COMBINED_PATH = os.path.join(SCRIPT_DIR, "results", "combined_report.txt")

CHARSET           = string.ascii_lowercase + string.digits
MAX_LENGTH        = 4
TOTAL_TIME_LIMIT  = 300   # seconds for the ENTIRE brute force run (5 min default)
TIME_PER_USER     = 30    # seconds per user at each length pass


# ============================================================
#  SECTION 1 — PARSE ATTACK 1 RESULTS
# ============================================================

def load_already_cracked(path: str) -> set[str]:
    """Load usernames already cracked by Attack 1 so we can skip them."""
    cracked = set()
    if not os.path.exists(path):
        print("  No Attack 1 results found — attacking all users.")
        return cracked

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if (line and
                not line.startswith("=") and
                not line.startswith("-") and
                not line.startswith("CRACKED") and
                not line.startswith("Username") and
                not line.startswith("Date") and
                not line.startswith("Cracked") and
                not line.startswith("Attempts") and
                not line.startswith("Time") and
                not line.startswith("Attack") and
                not line.startswith("No")):
                parts = line.split()
                if parts:
                    cracked.add(parts[0])

    print(f"  Skipping {len(cracked)} users already cracked by Attack 1.")
    return cracked


def parse_a1_results(path: str):
    """Parse Attack 1 result file for the combined report."""
    meta    = {}
    cracked = []

    if not os.path.exists(path):
        return None, []

    in_cracked_section = False

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()

            if stripped.startswith("Date"):
                meta["date"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Cracked") and not in_cracked_section:
                meta["cracked"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Attempts"):
                meta["attempts"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Time") and "Limit" not in stripped and not in_cracked_section:
                meta["time"] = stripped.split(":", 1)[1].strip()

            if stripped.startswith("CRACKED PASSWORDS"):
                in_cracked_section = True
                continue
            if in_cracked_section and stripped.startswith("---"):
                continue
            if in_cracked_section and stripped.startswith("Username"):
                continue
            if (in_cracked_section and stripped
                    and not stripped.startswith("=")
                    and not stripped.startswith("No")):
                parts = stripped.split()
                if len(parts) >= 2:
                    cracked.append((parts[0], parts[1]))

    return meta, cracked


# ============================================================
#  SECTION 2 — DATABASE
# ============================================================

def fetch_users(skip: set[str]) -> list[tuple[int, str, str]]:
    try:
        conn   = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, encrypted_nopep FROM users")
        all_users = cursor.fetchall()
        users     = [(uid, uname, uhash) for uid, uname, uhash in all_users if uname not in skip]
        print(f"  Found {len(all_users)} total — attacking {len(users)} "
              f"(skipping {len(skip)} already cracked).\n")
        return users
    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn'   in locals() and conn.is_connected(): conn.close()


# ============================================================
#  SECTION 3 — BRUTE FORCE ATTACK (Breadth-First)
# ============================================================

def brute_force_attack(users) -> tuple[list, int, float, float]:
    """
    Breadth-first brute force:
      Pass 1 — try every length-1 combo against ALL users
      Pass 2 — try every length-2 combo against ALL remaining users
      ...
    This finds short passwords faster than attacking one user at a time.
    Returns: (cracked_list, total_attempts, elapsed, speed)
    """
    print("=" * 60)
    print(f"  ATTACK 2 — Brute Force (Breadth-First)")
    print(f"  Target      : bcrypt hashes WITHOUT pepper")
    print(f"  Charset     : {CHARSET}")
    print(f"  Max length  : {MAX_LENGTH}")
    print(f"  Total limit : {TOTAL_TIME_LIMIT}s")
    print(f"  Per-user    : {TIME_PER_USER}s per length pass")
    print("=" * 60)

    cracked        = []          # list of (username, password)
    timed_out      = []
    cracked_set    = set()       # for O(1) skip lookup
    total_attempts = 0
    start_time     = time.time()
    global_timeout = False

    # Build a mutable dict: username -> (stored_hash, per-user deadline)
    # Deadline is reset each length pass
    remaining = {uname: uhash for _, uname, uhash in users}

    for length in range(1, MAX_LENGTH + 1):
        if global_timeout or not remaining:
            break

        combos_at_length = len(CHARSET) ** length
        print(f"\n  ── Length {length} — {combos_at_length:,} combos × "
              f"{len(remaining)} users ──")

        # Per-user deadline for THIS length pass
        user_deadlines = {uname: time.time() + TIME_PER_USER for uname in remaining}

        for combo in itertools.product(CHARSET, repeat=length):
            # Global timeout check
            if time.time() - start_time > TOTAL_TIME_LIMIT:
                print(f"\n  ⏱  Global time limit reached ({TOTAL_TIME_LIMIT}s).")
                global_timeout = True
                break

            guess          = ''.join(combo)
            users_to_remove = []

            for uname, uhash in list(remaining.items()):
                # Per-user time limit for this length pass
                if time.time() > user_deadlines[uname]:
                    timed_out.append(uname)
                    users_to_remove.append(uname)
                    continue

                total_attempts += 1
                try:
                    if bcrypt.checkpw(guess.encode('utf-8'), uhash.encode('utf-8')):
                        elapsed_so_far = time.time() - start_time
                        cracked.append((uname, guess))
                        cracked_set.add(uname)
                        users_to_remove.append(uname)
                        print(f"  [CRACKED]  {uname:<30} → '{guess}' "
                              f"(+{elapsed_so_far:.1f}s)")
                except Exception:
                    pass

            for uname in users_to_remove:
                remaining.pop(uname, None)

            if not remaining:
                break

        # Progress after each length pass
        print(f"  Length {length} done — "
              f"{len(cracked)} cracked, "
              f"{len(timed_out)} timed out, "
              f"{len(remaining)} remaining, "
              f"{total_attempts:,} total attempts")

    # Any users still in remaining after all lengths = genuinely failed
    actual_failed = list(remaining.keys())

    elapsed = time.time() - start_time
    speed   = total_attempts / elapsed if elapsed > 0 else 0

    # ---- Console summary ----
    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Cracked   : {len(cracked)} / {len(users)}")
    print(f"  Timed out : {len(timed_out)} / {len(users)} (exceeded time limit)")
    print(f"  Failed    : {len(actual_failed)} / {len(users)}")
    print(f"  Attempts  : {total_attempts:,}")
    print(f"  Time      : {elapsed:.2f}s")
    print(f"  Speed     : {speed:.1f} attempts/sec")
    print(f"{'=' * 60}")
    print(f"\n  NOTE: bcrypt cost 6 (demo) ≈ {speed:.0f} guesses/sec")
    print(f"  bcrypt cost 12 (production) ≈ 4 guesses/sec")
    print(f"  An 8-char password has {len(CHARSET)**8:,} combinations")
    if speed > 0:
        prod_speed = 4
        years = len(CHARSET) ** 8 / prod_speed / 3600 / 24 / 365
        print(f"  At cost 12 that would take {years:.0f}+ years to crack")

    return cracked, total_attempts, elapsed, speed


# ============================================================
#  SECTION 4 — SAVE A2 RESULTS
# ============================================================

def save_a2_results(cracked, elapsed, total_attempts, total_users, speed):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  ATTACK 2 — Brute Force Results\n")
        f.write(f"  Date      : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Charset   : {CHARSET}\n")
        f.write(f"  Max Len   : {MAX_LENGTH}\n")
        f.write(f"  Time Limit: {TIME_PER_USER}s per user per length\n")
        f.write(f"  Cracked   : {len(cracked)} / {total_users}\n")
        f.write(f"  Attempts  : {total_attempts:,}\n")
        f.write(f"  Time      : {elapsed:.2f}s\n")
        f.write(f"  Speed     : {speed:.1f} attempts/sec\n")
        f.write("=" * 60 + "\n\n")

        if cracked:
            f.write("CRACKED PASSWORDS:\n")
            f.write(f"{'Username':<30} {'Password'}\n")
            f.write("-" * 50 + "\n")
            for username, password in cracked:
                f.write(f"{username:<30} {password}\n")
        else:
            f.write("No passwords cracked.\n")

    print(f"\n✅ A2 results saved to: {OUTPUT_PATH}")


# ============================================================
#  SECTION 5 — COMBINED REPORT
# ============================================================

def save_combined_report(a1_meta, a1_cracked, a2_cracked, a2_meta):
    # Merge: A1 entries first, A2 fills in any new ones
    all_cracked = {}
    for username, password in a1_cracked:
        all_cracked[username] = (password, "Dictionary (A1)")
    for username, password in a2_cracked:
        if username not in all_cracked:
            all_cracked[username] = (password, "Brute Force (A2)")

    total_a1_attempts = int(a1_meta.get("attempts", "0").replace(",", "")) if a1_meta else 0
    total_a2_attempts = int(a2_meta.get("attempts", "0").replace(",", "")) if a2_meta else 0
    total_attempts    = total_a1_attempts + total_a2_attempts

    os.makedirs(os.path.dirname(COMBINED_PATH), exist_ok=True)
    with open(COMBINED_PATH, "w", encoding="utf-8") as f:

        # Header
        f.write("=" * 70 + "\n")
        f.write("  COMBINED ATTACK REPORT — Dictionary + Brute Force\n")
        f.write(f"  Generated     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Cracked : {len(all_cracked)}\n")
        f.write(f"  Total Attempts: {total_attempts:,}\n")
        f.write("=" * 70 + "\n\n")

        # Attack 1 summary
        f.write("-" * 70 + "\n")
        f.write("  ATTACK 1 — Dictionary Attack Summary\n")
        f.write("-" * 70 + "\n")
        if a1_meta:
            f.write(f"  Date     : {a1_meta.get('date',     'N/A')}\n")
            f.write(f"  Cracked  : {a1_meta.get('cracked',  'N/A')}\n")
            f.write(f"  Attempts : {a1_meta.get('attempts', 'N/A')}\n")
            f.write(f"  Time     : {a1_meta.get('time',     'N/A')}\n")
        else:
            f.write("  No Attack 1 results found.\n")
        f.write("\n")

        # Attack 2 summary
        f.write("-" * 70 + "\n")
        f.write("  ATTACK 2 — Brute Force Summary\n")
        f.write("-" * 70 + "\n")
        f.write(f"  Date       : {a2_meta['date']}\n")
        f.write(f"  Charset    : {a2_meta['charset']}\n")
        f.write(f"  Max Length : {a2_meta['max_len']}\n")
        f.write(f"  Time Limit : {a2_meta['time_limit']}\n")
        f.write(f"  Cracked    : {a2_meta['cracked']}\n")
        f.write(f"  Attempts   : {a2_meta['attempts']}\n")
        f.write(f"  Time       : {a2_meta['time']}\n")
        f.write(f"  Speed      : {a2_meta['speed']}\n")
        f.write("\n")

        # All cracked passwords
        f.write("=" * 70 + "\n")
        f.write("  ALL CRACKED PASSWORDS\n")
        f.write("=" * 70 + "\n")
        if all_cracked:
            f.write(f"  {'Username':<30} {'Password':<20} {'Method'}\n")
            f.write("  " + "-" * 66 + "\n")
            for username, (password, method) in sorted(all_cracked.items()):
                f.write(f"  {username:<30} {password:<20} {method}\n")
        else:
            f.write("  No passwords cracked by either attack.\n")
        f.write("\n")

        # Key findings
        f.write("=" * 70 + "\n")
        f.write("  KEY FINDINGS\n")
        f.write("=" * 70 + "\n")
        f.write(f"  • Dictionary attack cracked {len(a1_cracked)} account(s) using common passwords.\n")
        f.write(f"  • Brute force cracked {len(a2_cracked)} additional account(s).\n")
        f.write(f"  • Total compromised: {len(all_cracked)} account(s).\n")
        f.write(f"  • bcrypt slows brute force significantly — weak passwords are still at risk.\n")
        f.write(f"  • Adding a pepper (Attack 4) stops both attacks entirely.\n")
        f.write("=" * 70 + "\n")

    print(f"✅ Combined report saved to: {COMBINED_PATH}")


# ============================================================
#  ENTRY POINT
# ============================================================

if __name__ == "__main__":
    # Step 1: Load A1 cracked users to skip
    already_cracked = load_already_cracked(A1_RESULTS)

    # Step 2: Parse A1 results for the combined report
    a1_meta, a1_cracked = parse_a1_results(A1_RESULTS)

    # Step 3: Fetch users from DB (excluding A1 cracked)
    users = fetch_users(already_cracked)

    # Step 4: Run brute force
    a2_cracked_list, total_attempts, elapsed, speed = brute_force_attack(users)

    # Step 5: Save A2 individual results
    save_a2_results(a2_cracked_list, elapsed, total_attempts, len(users), speed)

    # Step 6: Build combined report
    a2_meta = {
        "date":       time.strftime('%Y-%m-%d %H:%M:%S'),
        "charset":    CHARSET,
        "max_len":    str(MAX_LENGTH),
        "time_limit": f"{TIME_PER_USER}s per user per length",
        "cracked":    f"{len(a2_cracked_list)} / {len(users)}",
        "attempts":   f"{total_attempts:,}",
        "time":       f"{elapsed:.2f}s",
        "speed":      f"{speed:.1f} attempts/sec",
    }
    save_combined_report(a1_meta, a1_cracked, a2_cracked_list, a2_meta)