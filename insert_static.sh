#!/bin/bash

echo 'Resetting database...'
mysql < Database/database_setup.sql

echo 'Inserting static 100 users...'
mysql < Database/static_users.sql

echo 'Encrypting passwords...'
python encryption/encrypt.py

echo 'Running password analysis...'
python analysis/analyze.py

echo 'Done.'