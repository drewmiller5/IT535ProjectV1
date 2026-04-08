import random
import os

# -------------------------
# Usernames setup (same as before)
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

# -------------------------
# Words for medium passwords
dictionary_words = [
    "baseball", "coffee", "tiger", "pizza", "soccer", "apple",
    "guitar", "banana", "chocolate", "steak", "football", "music",
    "summer", "winter", "hello", "friend", "sunshine", "mountain",
    "river", "ocean", "sky", "flower", "cat", "dog", "book", "fries",
    "car", "house", "tree", "phone", "computer", "cookie", "bicycle",
    "coffee", "pencil", "chair", "table", "window", "door", "shirt",
    "pants", "shoes", "hat", "glasses", "watch", "backpack", "wallet", 
    "key", "lamp", "candle", "mirror", "clock", "leopard", "turtle", 
    "dolphin", "eagle", "lion", "bear", "wolf", "fox", "rabbit","giraffe"
]

# -------------------------
# Randomized leet substitutions
leet_table = {'a':'@','e':'3','i':'1','o':'0','s':'$','t':'7'}

def random_leet(word):
    result = ""
    for c in word:
        # 50% chance to substitute a character
        if c.lower() in leet_table and random.random() < 0.5:
            result += leet_table[c.lower()]
        else:
            result += c
        # random capitalization
        if random.random() < 0.3:
            result = result[:-1] + result[-1].upper()
    return result

def generate_medium_password():
    num_words = random.randint(1,3)
    words_selected = random.sample(dictionary_words, num_words)
    password = "".join(random_leet(w) for w in words_selected)
    
    # Insert 1-3 random symbols or numbers in random positions
    symbols = "!@#$%^&*"
    for _ in range(random.randint(1,3)):
        idx = random.randint(0, len(password))
        insert_char = random.choice(symbols + "0123456789")
        password = password[:idx] + insert_char + password[idx:]
    
    return password

def generate_strong_password():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?"
    return ''.join(random.choices(chars, k=random.randint(12,18)))

def generate_password():
    r = random.randint(1,100)
    if r <= 10:   # weak
        return random.choice(["123456","password","abc123","welcome","qwerty","letmein"])
    elif r <= 70:  # medium
        return generate_medium_password()
    else:          # strong
        return generate_strong_password()

# -------------------------
# Generate users and append to SQL
usernames = set()
num_users = 50
users = []

for _ in range(num_users):
    uname = generate_username()
    while uname in usernames:
        uname = generate_username()
    usernames.add(uname)
    users.append((uname, generate_password()))

sql_file = "InsertUsers.sql"
mode = "a" if os.path.exists(sql_file) else "w"

with open(sql_file, mode) as f:
    for uname, pwd in users:
        f.write(f"INSERT INTO users (username, password) VALUES ('{uname}', '{pwd}');\n")

print(f"{num_users} INSERT statements written to {sql_file}")