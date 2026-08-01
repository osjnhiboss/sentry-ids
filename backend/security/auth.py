"""
Authentication utilities: password hashing + JWT issuing/verification.

Design notes for the report:
- Passwords are never stored in plaintext (werkzeug's salted hash).
- JWTs carry a 'role' claim so we can gate the /api/alerts endpoints to admins.
- Tokens expire (default 30 min) to limit the damage window of a stolen token.
"""
import datetime
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# In production this would come from an environment variable / secrets manager.
JWT_SECRET = "CHANGE_ME_IN_PRODUCTION_use_env_var"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30


def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, plain_password)


def issue_token(user_id: str, role: str = "user") -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    """Returns the payload dict, or None if invalid/expired."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
