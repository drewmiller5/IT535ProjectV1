# Authentication Security Research

IT535: Advanced Computer Security — Marymount University 2026

Controlled security research evaluating how modern authentication systems hold up against real attacks. Built a prototype authentication system, then attacked it — five attack types, two independent datasets, measurable results.

---

## Methodology

Two datasets run in parallel to separate reproducibility from generalization:

| Dataset | Users | Purpose |
|---|---|---|
| Static | 100 fixed users | Reproducible results — same output every run |
| Random | 50 randomized users | Validation — tests generalization across different data |

---

## Attack Pipeline

Five attacks run in sequence against the database:

```bash
./attack_overwrite.sh
```

| Attack | Script | What it tests |
|---|---|---|
| Dictionary | a1_dictionary_attack.py | Common password lists against hashed credentials |
| Brute Force | a2_brute_force.py | Exhaustive character-space search |
| Rainbow Table | a3_rainbow_table.py | Precomputed hash lookups |
| Pepper Guess | a4_pepper_guess.py | Attempts to recover the server-side pepper |
| Credential Stuffing | a5_credential_stuffing.py | Reused credential pairs across accounts |

---

## Setup

**Load the static dataset** (100 fixed users — same result every run):

```bash
./insert_static.sh
```

**Load the random dataset** (50 randomized users — different each run):

```bash
./insert_random.sh
```

**Run full pipelines:**

```bash
./full_static.sh    # insert static dataset + run all attacks
./full_random.sh    # insert random dataset + run all attacks
```

**Reset between runs:**

```bash
./attacks_reset.sh
```

---

## Built With

- Python
- SQLite
- Bash
