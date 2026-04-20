#!/bin/bash

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
rm -f attack/results/*.txt


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
python attack/a5_credential_stuffing.py"


echo "=============================="
echo " ATTACK PIPELINE COMPLETE"
echo "=============================="