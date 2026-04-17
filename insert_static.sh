#!/bin/bash

echo 'Resetting database...'
mysql < Database/DatabaseSetup.sql

echo 'Inserting static 100 users...'
mysql < Database/StaticUsers.sql

echo 'Running password analysis...'
python Analysis/analyze.py

echo 'Done.'