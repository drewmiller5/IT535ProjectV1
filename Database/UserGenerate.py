import random
import os
import mysql.connector
from mysql.connector import Error

# Output file lives next to this script
script_dir = os.path.dirname(os.path.abspath(__file__))
sql_file = os.path.join(script_dir, "InsertUsers.sql")

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',           # MAMP default
    'password': 'root',       # MAMP default (change only if you modified it)
    'database': 'user_system'
    # Uncomment below if your MAMP MySQL runs on port 8889:
    # 'port': 8889
}

# -------------------------
# 1. Fetch existing usernames from the DB (single connection, no duplicate block)
# -------------------------
existing_usernames = set()

try:
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    for (username,) in cursor.fetchall():
        existing_usernames.add(username)
    print(f"✅ Connected to MySQL successfully!")
    print(f"Found {len(existing_usernames)} existing usernames in the 'users' table.")
except Error as e:
    print(f"❌ Connection failed: {e}")
    print("\nTroubleshooting tips for MAMP:")
    print("   • Make sure MAMP is running (Apache + MySQL servers started)")
    print("   • Try changing password to '' (empty string) if 'root' doesn't work")
    print("   • Check MAMP → Open WebStart page → phpMyAdmin to verify credentials")
    exit(1)
finally:
    if 'cursor' in locals():
        cursor.close()
    if 'conn' in locals() and conn.is_connected():
        conn.close()

# -------------------------
# Username data
# -------------------------
first_names = {
    "alexander": ["alexander", "alex", "xander"],
    "michael": ["michael", "mike", "mickey", "mitch", "mikey"],
    "william": ["william", "will", "bill", "billy"],
    "james": ["james", "jim", "jimmy"],
    "katelynn": ["katelynn", "kate", "katty", "katie"],
    "sophia": ["sophia", "soph", "sophie"],
    "olivia": ["olivia", "liv", "livia"]
}

last_names = ["smith", "brennan", "johnson", "lee", "martin", "williams", "brown", "garcia"]

def generate_username():
    full_first = random.choice(list(first_names.keys()))
    first = random.choice(first_names[full_first])
    last = random.choice(last_names)
    number = str(random.randint(1, 99))
    formats = [
        f"{first}{last}",
        f"{first}{last}{number}",
        f"{first[0]}{last}",
        f"{first[0]}{last}{number}",
        f"{first}_{last}",
        f"{first}.{last}",
    ]
    return random.choice(formats)

def make_unique(base, taken):
    """If base is already taken, append incrementing numbers until unique: kbrennan -> kbrennan1 -> kbrennan2 ..."""
    if base not in taken:
        return base
    counter = 1
    while f"{base}{counter}" in taken:
        counter += 1
    return f"{base}{counter}"

# -------------------------
# Password generation
# -------------------------
dictionary_words = [
    "baseball", "coffee", "tiger", "pizza", "soccer", "apple",
    "guitar", "banana", "chocolate", "steak", "football", "music",
    "summer", "winter", "hello", "friend", "sunshine", "mountain",
    "river", "ocean", "sky", "flower", "cat", "dog", "book", "fries",
    "car", "house", "tree", "phone", "computer", "cookie", "bicycle",
    "pencil", "chair", "table", "window", "door", "shirt",
    "pants", "shoes", "hat", "glasses", "watch", "backpack", "wallet",
    "key", "lamp", "candle", "mirror", "clock", "leopard", "turtle",
    "dolphin", "eagle", "lion", "bear", "wolf", "fox", "rabbit", "giraffe"
]

leet_table = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}

def random_leet(word):
    result = ""
    for c in word:
        if c.lower() in leet_table and random.random() < 0.5:
            result += leet_table[c.lower()]
        else:
            result += c
        if random.random() < 0.3:
            result = result[:-1] + result[-1].upper()
    return result

def generate_medium_password():
    num_words = random.randint(1, 3)
    words_selected = random.sample(dictionary_words, num_words)
    password = "".join(random_leet(w) for w in words_selected)
    symbols = "!@#$%^&*"
    for _ in range(random.randint(1, 3)):
        idx = random.randint(0, len(password))
        insert_char = random.choice(symbols + "0123456789")
        password = password[:idx] + insert_char + password[idx:]
    return password

def generate_strong_password():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?"
    return ''.join(random.choices(chars, k=random.randint(12, 18)))

def generate_password():
    r = random.randint(1, 100)
    if r <= 10:
        return random.choice(["123456", "password", "abc123", "welcome", "qwerty", "letmein"])
    elif r <= 70:
        return generate_medium_password()
    else:
        return generate_strong_password()

# -------------------------
# Generate users — check against BOTH DB usernames and new ones being added this run
# -------------------------
# all_taken combines what's already in the DB with usernames generated in this session
all_taken = set(existing_usernames)
num_users = 50
users = []

for _ in range(num_users):
    base = generate_username()
    uname = make_unique(base, all_taken)  # appends 1, 2, 3... if already taken
    all_taken.add(uname)
    users.append((uname, generate_password()))

SQL_HEADER = """\
CREATE DATABASE IF NOT EXISTS `user_system`
    DEFAULT CHARACTER SET utf8mb4;

COMMIT;

-- -----------------------------------------------------
-- Use the database
-- -----------------------------------------------------
USE `user_system`;

CREATE TABLE IF NOT EXISTS `users` (
  `userid` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) UNIQUE NOT NULL,
  `password` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB;


"""

# Always overwrite — write the header first, then the INSERT statements
with open(sql_file, "w") as f:
    f.write(SQL_HEADER)
    for uname, pwd in users:
        f.write(f"INSERT INTO users (username, password) VALUES ('{uname}', '{pwd}');\n")

print(f"✅ {num_users} INSERT statements written to {sql_file}")