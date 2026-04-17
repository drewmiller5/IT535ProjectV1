import mysql.connector
from mysql.connector import Error
import re

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'user_system'
}

# -------------------------
# Common weak passwords — any of these is an instant "Weak" regardless of length
# -------------------------
COMMON_WEAK = {
    "123456", "password", "abc123", "welcome",
    "qwerty", "letmein", "iloveyou", "admin", "login"
}

# -------------------------
# Strength classifier
# -------------------------
def classify(password: str) -> str:
    """
    Weak   — common password, or under 6 characters
    Medium — 6-11 chars, with SOME complexity but not all criteria
    Strong — 12+ chars with uppercase, lowercase, digits, AND symbols all present
    """
    if password.lower() in COMMON_WEAK or len(password) < 6:
        return "Weak"

    has_upper   = bool(re.search(r'[A-Z]', password))
    has_lower   = bool(re.search(r'[a-z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_symbol  = bool(re.search(r'[^A-Za-z0-9]', password))
    all_criteria = has_upper and has_lower and has_digit and has_symbol

    if len(password) >= 12 and all_criteria:
        return "Strong"
    else:
        return "Medium"

# -------------------------
# Fetch all users from DB
# -------------------------
def fetch_users() -> list[tuple[str, str]]:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM users ORDER BY userid")
        rows = cursor.fetchall()
        print(f"✅ Connected. Found {len(rows)} users.\n")
        return rows
    except Error as e:
        print(f"❌ Database error: {e}")
        exit(1)
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

# -------------------------
# Main analysis
# -------------------------
def analyze():
    users = fetch_users()

    weak   = []
    medium = []
    strong = []

    for username, password in users:
        level = classify(password)
        if level == "Weak":
            weak.append((username, password))
        elif level == "Medium":
            medium.append((username, password))
        else:
            strong.append((username, password))

    total = len(users)

    # -------------------------
    # Print summary table
    # -------------------------
    print("=" * 60)
    print(f"  PASSWORD STRENGTH ANALYSIS  —  {total} users total")
    print("=" * 60)

    for label, group, color in [
        ("Weak",   weak,   "❌"),
        ("Medium", medium, "🟨"),
        ("Strong", strong, "✅"),
    ]:
        count = len(group)
        pct   = (count / total * 100) if total else 0
        bar   = "█" * int(pct / 2)  # 50-char max bar
        print(f"\n{color} {label:6}  {count:3} users  ({pct:5.1f}%)  {bar}")
        for username, password in group:
            print(f"     {username:<30} {password}")

    print("\n" + "=" * 60)
    print(f"  Weak:   {len(weak):3}  |  Medium: {len(medium):3}  |  Strong: {len(strong):3}")
    print("=" * 60)

if __name__ == "__main__":
    analyze()