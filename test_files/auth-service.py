import hashlib

PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...
U29tZVN1cGVyU2VjcmV0S2V5Q29udGVudA==
-----END PRIVATE KEY-----"""

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(token: str):
    if token == "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9":
        return True
    return False