"""
ThreatLens MongoDB Management and Verification Utility.
Run this script to inspect MongoDB collections, verify documents, and produce
output suitable for college project evaluation and report screenshots.

Usage:
    python database/mongo_cli.py --status
    python database/mongo_cli.py --inspect
    python database/mongo_cli.py --migrate
"""

import sys
import json
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import Config
from database.mongo_db import mongo_manager
from database.db import migrate_sqlite_to_mongo, get_db_status


def show_status():
    print("=" * 65)
    print("  THREATLENS - MONGODB STORAGE & CONNECTION STATUS")
    print("=" * 65)
    status = get_db_status()
    print(f"[*] Target URI:       {status['mongo_uri']}")
    print(f"[*] Database Name:    {status['mongo_db_name']}")
    print(f"[*] MongoDB Online:   {'[YES] Connected' if status['mongo_connected'] else '[NO] Disconnected'}")
    print(f"[*] Active Backend:   {status['active_backend']}")
    print(f"[*] SQLite Backup:    {status['sqlite_scans_count']} scans recorded")

    if status["mongo_connected"]:
        print("\n--- MongoDB Collection Counts ---")
        for coll, count in status["mongo_counts"].items():
            print(f"  • {coll.ljust(28)}: {count} documents")
    else:
        print(f"\n[!] Connection Error: {status['mongo_error']}")
        print("\n[i] Troubleshooting instructions for college viva:")
        print("    1. If running local MongoDB, ensure service is started: `net start MongoDB` or run `mongod`.")
        print("    2. If using MongoDB Atlas (cloud), update MONGO_URI in your .env file:")
        print("       MONGO_URI=mongodb+srv://<user>:<pwd>@cluster0.xxxxx.mongodb.net/threatlens")
    print("=" * 65)


def inspect_collections():
    if not mongo_manager.connect():
        print(f"[!] Cannot connect to MongoDB at {Config.MONGO_URI}: {mongo_manager.get_last_error()}")
        return

    db = mongo_manager.db
    print("\n" + "=" * 65)
    print("  THREATLENS — DETAILED MONGODB DOCUMENT INSPECTION")
    print("=" * 65)

    collections = ["scans", "findings", "threat_intelligence_results", "ai_analyses"]
    for c_name in collections:
        coll = db[c_name]
        count = coll.count_documents({})
        print(f"\n>>> Collection: '{c_name}' (Total Documents: {count})")
        sample = coll.find_one({}, {"_id": 0})
        if sample:
            preview = json.dumps(sample, indent=2, default=str)
            # Truncate preview if too long
            lines = preview.splitlines()
            if len(lines) > 25:
                preview = "\n".join(lines[:25]) + f"\n  ... [{len(lines) - 25} lines truncated for readability] ..."
            print(preview)
        else:
            print("    (Collection is currently empty)")
    print("=" * 65)


def do_migration():
    print("[*] Initiating SQLite-to-MongoDB migration...")
    if not mongo_manager.connect():
        print(f"[!] MongoDB is not reachable: {mongo_manager.get_last_error()}")
        return
    count = migrate_sqlite_to_mongo()
    print(f"[+] Migration complete: {count} scans migrated into MongoDB.")
    show_status()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatLens MongoDB Management Utility")
    parser.add_argument("--status", action="store_true", help="Display MongoDB connection and counts")
    parser.add_argument("--inspect", action="store_true", help="Print sample documents from all 4 collections")
    parser.add_argument("--migrate", action="store_true", help="Migrate SQLite scans to MongoDB")

    args = parser.parse_args()
    if args.inspect:
        inspect_collections()
    elif args.migrate:
        do_migration()
    else:
        show_status()
