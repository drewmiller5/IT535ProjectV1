#!/bin/bash

echo "=============================="
echo " FULL STATIC PIPELINE"
echo "=============================="

# -------------------------
# RESET DATABASE
# -------------------------
echo "Resetting database..."
mysql < Database/database_setup.sql


# -------------------------
# STATIC DATA ONLY
# -------------------------
echo "Inserting base static users..."
mysql < Database/base_users.sql

echo "Inserting static users..."
mysql < Database/static_users.sql


# -------------------------
# CLEAN OLD OUTPUTS (CRITICAL)
# -------------------------
echo "Cleaning old analysis results..."
rm -f attack/results/*.txt


# -------------------------
# ENCRYPTION STEP
# -------------------------
echo "Encrypting passwords..."
python encryption/encrypt.py


echo "Running password analysis..."
python analysis/analyze.py


echo "=============================="
echo " STATIC PIPELINE COMPLETE"
echo "=============================="