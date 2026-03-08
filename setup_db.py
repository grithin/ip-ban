"""
Run once to initialize the database and directory structure.
  python3 setup_db.py
"""
import os
import models
import db

# Create tables
models.Base.metadata.create_all(db.engine)
print("Database initialized: sqlite3.db")

# Create input/output directories
dirs = [
    'ip-ban-lists',
    'ip-ban-cidr-lists',
    'ip-ban-whitelist',
    'out',
]
for d in dirs:
    os.makedirs(d, exist_ok=True)
    print(f"Directory ready: {d}/")

print("\nSetup complete. Next steps:")
print("  1. Add IP log CSVs to ip-ban-lists/")
print("  2. Download external lists into ip-ban-cidr-lists/ (see README Sources section)")
print("  3. python3 main.py full")
