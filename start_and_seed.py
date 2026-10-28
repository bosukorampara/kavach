#!/usr/bin/env python3
"""
Script to seed test data for KAVACH dashboard
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def seed_data():
    """Seed threat testcases into the database"""
    try:
        from utils.data_generator import seed_threat_testcases
        
        db_path = project_root / 'data' / 'audit_trail.db'
        catalog_path = project_root / 'utils' / 'threats_catalog.json'
        
        print("Seeding threat testcases...")
        count = seed_threat_testcases(
            db_path=str(db_path),
            catalog_path=str(catalog_path),
            days=7
        )
        print(f"✓ Seeded {count} threat testcase events")
        return True
    except Exception as e:
        print(f"Error seeding data: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("KAVACH - Seeding Test Data")
    print("=" * 60)
    
    # Seed data
    if seed_data():
        print("\n✓ Data seeding complete!")
        print("\nNow start the server with:")
        print("   python main.py")
        print("\nThen refresh your dashboard to see the charts!")
    else:
        print("\n✗ Failed to seed data. Check errors above.")
        sys.exit(1)

