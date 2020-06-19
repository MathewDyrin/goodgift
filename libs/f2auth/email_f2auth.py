import time
import datetime
import random


class EmailSecondFA:
    __fa2_email_dict = {}
    __EXPIRES_DELTA = datetime.timedelta(minutes=2)

    @classmethod
    def generate_2fa_code(cls, token: str) -> str:
        if cls.__fa2_email_dict.get(token):
            del cls.__fa2_email_dict[token]
        code_2fa = ""
        for i in random.sample(range(10), 6):
            code_2fa += str(i)
        code_living_cycle = time.time() + cls.__EXPIRES_DELTA.seconds
        cls.__fa2_email_dict.update({
            token: {
                "code_living_cycle": code_living_cycle,
                "code_2fa": code_2fa
            }
        })

        return code_2fa

    @classmethod
    def check_2fa_code(cls, token: str, code: str) -> bool:
        #  можно возвращать кортеж значений (response: bool, message: str)
        identity_2fa = cls.__fa2_email_dict.get(token)
        if identity_2fa:
            if code == identity_2fa["code_2fa"]:
                if identity_2fa["code_living_cycle"] > time.time():
                    del cls.__fa2_email_dict[token]
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    @classmethod
    def token_expiration_delta(cls):
        return cls.__EXPIRES_DELTA

    @classmethod
    def force_revoke_2fa_code(cls, token: str) -> None:
        identity_2fa = cls.__fa2_email_dict.get(token)
        if identity_2fa:
            del cls.__fa2_email_dict[token]
