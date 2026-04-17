#!/bin/bash

echo 'Resetting database...'
mysql < Database/DatabaseSetup.sql

echo 'Inserting base users...'
mysql < Database/BaseUsers.sql

echo 'Generating random users (Python)...'
python Database/UserGenerate.py

echo 'Inserting generated users...'
mysql < Database/InsertUsers.sql

echo 'Encrypting passwords...'
python Encryption/Encrypt.py

echo 'Running password analysis...'
python Analysis/analyze.py

echo 'Done.'