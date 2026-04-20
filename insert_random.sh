#!/bin/bash

echo "=============================="
echo " FULL SYSTEM PIPELINE"
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
rm -f attack/results/*.txt


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
echo " DONE"
echo "=============================="