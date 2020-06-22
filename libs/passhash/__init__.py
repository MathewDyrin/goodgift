import hashlib
from typing import Tuple
from uuid import uuid4


class PassCrypt:

    __ITERATIONS = 100000

    @classmethod
    def generate_password_hash(cls, user_password: str) -> Tuple[str, str]:
        password_salt = uuid4().hex
        password_hash = hashlib.sha256(
            hashlib.pbkdf2_hmac(
                "sha256",
                user_password.encode("utf-8"),
                salt=password_salt.encode("utf-8"),
                iterations=cls.__ITERATIONS
            )
        ).hexdigest()
        return password_salt, password_hash

    @classmethod
    def check_password_hash(cls, checking_hash, checking_salt: str, outer_password: str) -> bool:
        check_key = hashlib.sha256(
            hashlib.pbkdf2_hmac(
                "sha256",
                outer_password.encode("utf-8"),
                salt=checking_salt.encode("utf-8"),
                iterations=cls.__ITERATIONS
            )
        ).hexdigest()
        return checking_hash == check_key
