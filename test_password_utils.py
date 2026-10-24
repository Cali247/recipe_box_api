from password_utils import hash_password, verify_password

password = "test-password-123"

stored = hash_password(password)
print("Stored hash:", stored)

print("Correct password check:", verify_password(stored, "test-password-123"))
print("Wrong password check:", verify_password(stored, "wrong-pass"))