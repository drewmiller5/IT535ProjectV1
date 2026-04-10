#!/bin/bash

echo 'Resetting database...'
mysql < DatabaseSetup.sql 

echo 'Inserting base users...'
mysql < BaseUsers.sql 

echo 'Generating random users (Python)...'
python UserGenerate.py 

echo 'Inserting generated users...'
mysql < InsertUsers.sql 

echo 'Done.'