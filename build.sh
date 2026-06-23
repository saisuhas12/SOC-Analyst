#!/usr/bin/env bash
# exit on error
set -o errexit

# Install pip packages
pip install -r requirements.txt

# Create upload directories inside the persistent mount
mkdir -p app/static/uploads/reports
mkdir -p app/static/uploads/screenshots
mkdir -p app/static/uploads/logs

# Initialize, stamp migration, and seed DB tables
python init_db.py
