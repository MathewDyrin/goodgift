import time
from flask import request, url_for
from requests import Response
from src.extensions import db
from src.models.confirmation import ConfirmationModel
from libs.mail.mailgun import MailGun
from libs.serving import response_quote
from libs.f2auth.email_f2auth import EmailSecondFA


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(80), nullable=False)
    password_salt = db.Column(db.String(80), nullable=False)
    session_key = db.Column(db.String(256))  # just for development
    balance = db.Column(db.Integer, default=0)
    second_fa_enabled = db.Column(db.Boolean, nullable=False, default=False)  # MAY BE NOT PRODUCTION IMPLEMENTING
    token_2fa = db.Column(db.String(120))
    name = db.Column(db.String(80))
    surname = db.Column(db.String(80))
    profile_pic = db.Column(db.String(64), nullable=False, default="gg_default_profile_pic.png")
    locality = db.Column(db.String(120))

    confirmation = db.relationship(
        "ConfirmationModel",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )

    @property
    def most_recent_confirmation(self) -> "ConfirmationModel":
        return self.confirmation.order_by(db.desc(ConfirmationModel.expire_at)).first()

    def turn_to_json(self):
        return {"username": self.username,
                "id": self.id,
                "locality": self.locality,
                "profile_pic": self.profile_pic
                }

    @classmethod
    def find_by_id(cls, _id: int) -> "UserModel":
        return cls.query.get(_id)

    @classmethod
    def find_by_email(cls, email: str) -> "UserModel":
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_username(cls, username: str) -> "UserModel":
        return cls.query.filter_by(username=username).first()

    @classmethod
    # TODO: TESTING VERSION MAYBE
    def find_by_token_2fa(cls, token: str) -> "UserModel":
        return cls.query.filter_by(token_2fa=token).first()

    @classmethod
    def find_by_session_key(cls, key: str) -> "UserModel":
        return cls.query.filter_by(session_key=key).first()

    @classmethod
    def find_by_locality(cls, locality: str):
        pass

    def confirm(self) -> Response:
        link = request.url_root[0:-1] + url_for(
            "confirmation", confirmation_id=self.most_recent_confirmation.id
        )
        subject = f"{response_quote('user_registration_confirmation_subject')}"
        text = f"{response_quote('user_registration_confirmation_text')} {link}"
        html = f'<html>{response_quote("user_registration_confirmation_text")}: <a href="{link}">{link}</a></html>'

        return MailGun.send_email_message([self.email], subject, text, html)

    def password_reset_request(self, code: str) -> Response:
        subject = f"{response_quote('user_password_restore_subject').format(self.email)}"
        text = f"{response_quote('user_password_restore_text').format(code)}"
        html = f'<html>{response_quote("user_password_restore_text").format(code)}</html>'

        return MailGun.send_email_message([self.email], subject, text, html)

    def send_email_2fa_code(self, code: str) -> Response:
        subject = response_quote("email2fa_code_mail_subject")
        text = response_quote("email2fa_code_mail_text")
        html = f'<html>' \
               f'{response_quote("email2fa_code_mail_text").format(EmailSecondFA.token_expiration_delta().seconds // 60)} ' \
               f'<h4>{code}</h4></html>'
        return MailGun.send_email_message([self.email], subject, text, html)

    def save_to_db(self) -> None:
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self) -> None:
        db.session.delete(self)
        db.session.commit()
