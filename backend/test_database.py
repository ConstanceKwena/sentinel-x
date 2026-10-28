
from backend.database import DATABASE_PATH, initialize_database, get_connection


def main():
    initialize_database()
    print(f"Database location: {DATABASE_PATH}")

    connection = get_connection()
    try:
        result = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'"
        ).fetchone()

        if result:
            print("SUCCESS: security_events table exists.")
        else:
            print("ERROR: security_events table was not found.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
