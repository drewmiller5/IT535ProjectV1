#!/bin/bash

echo "=============================="
echo " FULL RANDOM PIPELINE"
echo "=============================="

# -------------------------
# RESET DATABASE
# -------------------------
echo "Resetting database..."
mysql < Database/database_setup.sql


# -------------------------
# DATA SETUP (choose one flow)
# -------------------------
echo "Inserting base users..."
mysql < Database/base_users.sql

echo "Generating random users (Python)..."
python Database/user_generate.py

echo "Inserting generated users..."
mysql < Database/insert_users.sql


# -------------------------
# CLEAN OLD OUTPUTS (IMPORTANT FIX)
# -------------------------
echo "Cleaning old analysis results..."
rm -f rm -f attack/results/*


# -------------------------
# ENCRYPTION STEP
# -------------------------
echo "Encrypting passwords..."
python encryption/encrypt.py


# -------------------------
# ANALYSIS
# -------------------------
echo "Running password analysis..."
python analysis/analyze.py


echo "=============================="
echo " ATTACK PIPELINE"
echo "=============================="

# -------------------------
# SAFETY CHECK (optional but smart)
# -------------------------
if [ ! -d "attack/results" ]; then
  echo "Creating results directory..."
  mkdir -p attack/results
fi


# -------------------------
# CLEAN OLD OUTPUTS (CRITICAL)
# -------------------------
echo "Cleaning previous attack results..."
rm -f rm -f attack/results/*


# -------------------------
# RUN ATTACKS IN ORDER
# -------------------------
echo "Running Attack 1 — Dictionary"
python attack/a1_dictionary_attack.py

echo "Running Attack 2 — Brute Force"
python attack/a2_brute_force.py

echo "Running Attack 3 — Rainbow Table"
python attack/a3_rainbow_table.py

echo "Running Attack 4 — Pepper Guess"
python attack/a4_pepper_guess.py

echo "Running Attack 5 — Credential Stuffing"
python attack/a5_credential_stuffing.py


echo "=============================="
echo " ATTACK PIPELINE COMPLETE"
echo "=============================="

echo "Done."