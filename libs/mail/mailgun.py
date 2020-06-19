import json
from typing import List
from requests import post, Response
from libs.serving import response_quote


class MailGunException(Exception):
    """
    MAILGUN API custom exceptions
    """

    def __init__(self, message: str):
        super().__init__(message)


class MailGun:
    """
    MAILGUN API for sending emails
    """

    with open('libs/mail/mailgun_config.json', 'r') as f:
        data_json = json.load(f)
        BASE_URL = data_json["mailgun_base_message_url"]
        MAILGUN_DOMAIN_NAME = data_json["mailgun_domain_name"]
        MAILGUN_API_KEY = data_json["mailgun_api_key"]
        MAILGUN_FROM_EMAIL = data_json["mailgun_from_email"]

    # TODO: arguments in the function
    @classmethod
    def send_email_message(cls, email: List[str], subject: str, text: str, html: str) -> Response:
        response = post(
            cls.BASE_URL,
            auth=("api", cls.MAILGUN_API_KEY),
            data={"from": f"devGoodGift {cls.MAILGUN_FROM_EMAIL}",
                  "to": email,
                  "subject": subject,
                  "text": text,
                  "html": html,
                  },
        )

        if response.status_code != 200:
            raise MailGunException(response_quote("mailgun_sending_error"))
        return response
