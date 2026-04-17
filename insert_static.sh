#!/bin/bash

echo 'Resetting database...'
mysql < Database/DatabaseSetup.sql

echo 'Inserting static 100 users...'
mysql < Database/StaticUsers.sql

echo 'Encrypting passwords...'
python Encryption/Encrypt.py

echo 'Running password analysis...'
python Analysis/analyze.py

echo 'Done.'