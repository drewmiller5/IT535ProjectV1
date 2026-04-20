import bcrypt
import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'user_system'
    # 'port': 8889
}

PEPPER = "ch@ng3m3inPr0d!"

# -------------------------
# rounds=6 for demo/research purposes — fast enough to run quickly
# rounds=12 is production standard (~250ms per hash)
# rounds=6 is ~4ms per hash — same concept, just faster to demonstrate
# Note this in your paper
# -------------------------
BCRYPT_ROUNDS = 6

def encrypt_passwords():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT userid, password
            FROM users
            WHERE encrypted_password IS NULL
               OR encrypted_password = ''
        """)
        users = cursor.fetchall()

        print(f"Found {len(users)} users to encrypt...")
        print(f"Using bcrypt rounds={BCRYPT_ROUNDS} (demo mode)\n")

        encrypted_count = 0

        for userid, plaintext in users:

            # bcrypt + pepper (secure — attacker cannot crack without pepper)
            peppered      = plaintext + PEPPER
            hashed_secure = bcrypt.hashpw(peppered.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

            # bcrypt only, no pepper (vulnerable — weak passwords will crack)
            hashed_nopep  = bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

            cursor.execute(
                """
                UPDATE users
                SET encrypted_password = %s,
                    encrypted_nopep    = %s
                WHERE userid = %s
                  AND encrypted_password IS NULL
                """,
                (hashed_secure.decode('utf-8'), hashed_nopep.decode('utf-8'), userid)
            )

            print(f"  [OK] userid {userid} — encrypted")
            encrypted_count += 1

        conn.commit()

        print("\n" + "=" * 40)
        print(f"  Encrypted : {encrypted_count}")
        print(f"  Rounds    : {BCRYPT_ROUNDS} (demo)")
        print("=" * 40)
        print("✅ Encryption complete.")
        print("   encrypted_password — bcrypt + pepper (secure)")
        print("   encrypted_nopep    — bcrypt only (vulnerable)")

    except Error as e:
        print(f"❌ Database error: {e}")

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

if __name__ == "__main__":
    encrypt_passwords()