#!/usr/bin/env python3
"""
Script to seed sample data into the AtendeX database.
Run this script to populate the database with sample users, courses, etc.
"""

import os
from index import app, init_db

if __name__ == '__main__':
    # Set environment variable to enable seeding
    os.environ['SEED_SAMPLE'] = '1'
    print('Seeding sample data...')
    with app.app_context():
        init_db()
    print('Sample data seeded successfully.')
