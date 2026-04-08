#!/bin/bash

echo $d': Inserting test users...' 
mysql < DatabaseSample.sql 2>&1 