#!/bin/bash

echo 'Resetting database...'
mysql < Database/database_setup.sql

echo 'Inserting base users...'
mysql < Database/base_users.sql

echo 'Generating random users (Python)...'
python Database/user_generate.py

echo 'Inserting generated users...'
mysql < Database/insert_users.sql

echo 'Encrypting passwords...'
python encryption/encrypt.py

echo 'Running password analysis...'
python analysis/analyze.py

echo 'Done.'