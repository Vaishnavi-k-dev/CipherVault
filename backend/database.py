from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

MONGO_URI = "mongodb://127.0.0.1:27017/"

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000
)

db = client["CipherVaultDB"]

users_collection = db["users"]
files_collection = db["files"]
security_logs_collection = db["security_logs"]
users_collection.create_index("email", unique=True)


def test_connection():
    try:
        client.admin.command("ping")
        print("MongoDB connected successfully!")
        print("Database:", db.name)
        print("Collections ready:")
        print("- users")
        print("- files")
        print("- security_logs")
        return True

    except ConnectionFailure as error:
        print("MongoDB connection failed:", error)
        return False


if __name__ == "__main__":
    test_connection()