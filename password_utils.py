from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(plain_password: str) -> str:
    """Return a secure hash of the given plaintext password."""
    # Explicitly pick a method that doesn't need hashlib.scrypt
    return generate_password_hash(plain_password, method="pbkdf2:sha256")


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Return True if the candidate_password matches the stored hash."""
    return check_password_hash(stored_hash, candidate_password)