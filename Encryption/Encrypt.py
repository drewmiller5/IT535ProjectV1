import bcrypt
import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'user_system'
}

PEPPER = "ch@ng3m3inPr0d!"

def encrypt_passwords():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Only fetch users where encrypted_password is not yet set
        cursor.execute("""
            SELECT userid, password
            FROM users
            WHERE encrypted_password IS NULL
               OR encrypted_password = ''
        """)
        users = cursor.fetchall()

        print(f"Found {len(users)} users to encrypt...\n")

        encrypted_count = 0

        for userid, plaintext in users:
            # Hash password with pepper
            peppered = plaintext + PEPPER
            hashed = bcrypt.hashpw(
                peppered.encode('utf-8'),
                bcrypt.gensalt(rounds=12)
            )

            # Store ONLY in encrypted_password — password column is untouched
            cursor.execute(
                """
                UPDATE users
                SET encrypted_password = %s
                WHERE userid = %s
                  AND encrypted_password IS NULL
                """,
                (hashed.decode('utf-8'), userid)
            )

            print(f"  [OK] userid {userid} — encrypted")
            encrypted_count += 1

        conn.commit()

        print("\n" + "=" * 40)
        print(f"Encrypted : {encrypted_count}")
        print(f"Skipped   : {len(users) - encrypted_count}")
        print("=" * 40)
        print("✅ Encryption complete.")

    except Error as e:
        print(f"❌ Database error: {e}")

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()

if __name__ == "__main__":
    encrypt_passwords()