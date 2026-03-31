# generate_data.py
# Purpose: Generate 100 synthetic estate beneficiary records
# and store them in a SQLite database.
#
#Why synthetic data? We cannot use real client data.
# Faker generates realistic Australian records for testing and development.
# SQLite stores everything locally - no Azure cost, no setup

import sqlite3 
import random
from faker import Faker
from datetime import datetime, date

# Set up Faker to generate Australian data
fake = Faker('en_AU')

# Set a seed so results are reproducible
Faker.seed(42)
random.seed(42)

# These lists simulate real Public Trustee data categories
ESTATE_STATUSES = [
    'Active',
    'Closed',
    'Pending',
    'Under Review',
    'Suspended'
]

DATA_CLASSIFICATIONS = [
    'Public',
    'Internal',
    'Confidential',
    'Restricted'
]

RELATIONSHIP_TYPES = [
    'Beneficiary',
    'Executor',
    'Administrator',
    'Guardian',
    'Trustee'
]

REMEDIATION_STATUSES = [
    'Not Reviewed',
    'Reviewed - No Action',
    'Reviewed - Remediated',
    'Escalated',
    'Pending Review'
]

def generate_estate_record(record_id):
    # Generate a realistic date of birth (age 18-95)
    dob = fake.date_of_birth(minimum_age=18, maximum_age=95)

    # Generate estate opened date (between 1990 and today)
    estate_opened = fake.date_between(
        start_date=date(1990, 1, 1),
        end_date=date.today()
    )

    return {
        # Identity fields
        'record_id': record_id,
        'title': random.choice(['Mr', 'Mrs', 'Ms', 'Dr', 'Miss']),
        'first_name': fake.first_name(),
        'middle_name': fake.first_name(),
        'last_name': fake.last_name(),
        'gender': random.choice(['Male', 'Female', 'Non-binary']),
        'date_of_birth': dob.strftime('%Y-%m-%d'),
        'place_of_birth': fake.city(),
        'nationality': 'Australian',

        # Contact fields - HIGH sensitivity PTT
        'email': fake.email(),
        'phone_number': fake.phone_number(),
        'address': fake.street_address(),
        'suburb': fake.city(),
        'state': fake.state_abbr(),
        'postcode': fake.postcode(),
        'country': 'Australia',

        # Government identifiers - HIGHEST sensitivity PII
        'tfn': f'{random.randint(100, 999)} {random.randint(100, 999)} {random.randint(100, 999)}',
        'medicare_number': f'{random.randint(2000, 6999)}{random.randint(10000, 99999)}{random.randint(1,9)}',

        # Estate fields
        'estate_id': f'QPT-{record_id:04d}',
        'relationship_type': random.choice(RELATIONSHIP_TYPES),
        'estate_status': random.choice(ESTATE_STATUSES),
        'estate_opened_date': estate_opened.strftime('%Y-%m-%d'),
        'estimated_estate_value': round(random.uniform(10000, 2500000), 2),

        # Financial fields - HIGH sensitivity PII
        'bank_bsb': f'{random.randint(100, 999)}-{random.randint(100,999)}',
        'bank_account': f'{random.randint(10000000, 99999999)}',
        'bank_name': random.choice([
            'Commonwealth Bank',
            'Westpac',
            'ANZ',
            'NAB',
            'Bank of Queensland'
        ]),

        # Data governance fields
        'data_classification': random.choice(DATA_CLASSIFICATIONS),
        'remediation_status': random.choice(REMEDIATION_STATUSES),
        'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'reviewed_by_dqo': random.choice([None, 'DQO-001', 'DQO-002', 'DQO-003']),
        'pii_scan_completed': random.choice([True, False]),
        'notes': random.choice([
            None,
            'Pending document verification',
            'Awaiting executor confirmation',
            'Financial review in progress',
            'Address verification required'
        ])
    }

def create_database():
    # Connect to SQLite database
    # If the file doesn't exist, SQLite creates it automatically
    conn = sqlite3.connect('database/guardian.db')

    # A cursor is what actually executes SQL commands
    cursor = conn.cursor()

    # Create the table if it doesn't already exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS estate_records (
            record_id INTEGER PRIMARY KEY,
            title TEXT,
            first_name TEXT,
            middle_name TEXT,
            last_name TEXT,
            gender TEXT,
            date_of_birth TEXT,
            place_of_birth TEXT,
            nationality TEXT,
            email TEXT,
            phone_number TEXT,
            address TEXT,
            suburb TEXT,
            state TEXT,
            postcode TEXT,
            country TEXT,
            tfn TEXT,
            medicare_number TEXT,
            estate_id TEXT,
            relationship_type TEXT,
            estate_status TEXT,
            estate_opened_date TEXT,
            estimated_estate_value REAL,
            bank_bsb TEXT,
            bank_account TEXT,
            bank_name TEXT,
            data_classification TEXT,
            remediation_status TEXT,
            created_date TEXT,
            last_updated TEXT,
            reviewed_by_dqo TEXT,
            pii_scan_completed INTEGER,
            notes TEXT
        )
    ''')

    # Save the changes
    conn.commit()

    return conn, cursor

def populate_database(conn, cursor):
    print("Generating 100 synthetic estate records...")

    records_inserted = 0

    for record_id in range(1, 101):
        # Generate one record
        record = generate_estate_record(record_id)

        # Insert into database using SQL
        cursor.execute('''
            INSERT OR IGNORE INTO estate_records VALUES (
                :record_id, :title, :first_name, :middle_name,
                :last_name, :gender, :date_of_birth, :place_of_birth,
                :nationality, :email, :phone_number, :address,
            :suburb, :state, :postcode, :country,
            :tfn, :medicare_number, :estate_id,
            :relationship_type, :estate_status,
            :estate_opened_date, :estimated_estate_value,
            :bank_bsb, :bank_account, :bank_name,
            :data_classification, :remediation_status,
            :created_date, :last_updated, :reviewed_by_dqo,
            :pii_scan_completed, :notes
        )
    ''', record)

        records_inserted += 1

    # Save all inserts at once
    conn.commit()

    print(f"Successfully inserted {records_inserted} records.")
    return records_inserted

def verify_database(cursor):
    # Count total records
    cursor.execute('SELECT COUNT(*) FROM estate_records')
    total = cursor.fetchone()[0]

    # Count records by classification
    cursor.execute('''
        SELECT data_classification, COUNT(*) as count
        FROM estate_records
        GROUP BY data_classification
        ORDER BY count DESC
    ''')
    classifications = cursor.fetchall()

    # Count PII scan status
    cursor.execute('''
        SELECT pii_scan_completed, COUNT(*) as count
        FROM estate_records
        GROUP BY pii_scan_completed
    ''')
    scan_status = cursor.fetchall()

    print(f"\n--- DATABASE VERIFICATION ---")
    print(f"Total records: {total}")
    print(f"\nRecords by classification:")
    for classification, count in classifications:
        print(f"  {classification}: {count}")
    print(f"\nPII scan status:")
    for status, count in scan_status:
        label = "Scanned" if status == 1 else "Not scanned"
        print(f"  {label}: {count}")
    print(f"----------------------------\n")
    
    return total
    
def main():
    print("Starting GUARDIAN data generation...")
    print("="*45)

    # Step 1: Create database and table
    print("\nStep 1: Creating database...")
    conn, cursor = create_database()
    print("Database created: database/guardian.db")

    # Step 2: Populate with synthetic records
    print("\nStep 2: Generating synthetic records...")
    records_inserted = populate_database(conn, cursor)

    # Step 3: Verify everything loaded correctly
    print("\nStep 3: Verifying data...")
    verify_database(cursor)

    # Step 4: Close the database connection
    conn.close()
    print("Database connection closed.")
    print("="*45)
    print("GUARDIAN data generation complete!")
    print("File location: database/guardian.db")

if __name__ == "__main__":
    main()