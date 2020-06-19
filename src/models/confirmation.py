import time
from uuid import uuid4
from src.extensions import db

EXPIRATION_DELTA = 1800  # 1800 seconds == 30 minutes


class ConfirmationModel(db.Model):

    __tablename__ = 'confirmations'

    id = db.Column(db.String(50), primary_key=True)
    expire_at = db.Column(db.Integer, nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("UserModel")

    def __init__(self, user_id: int, **kwargs):
        super().__init__(**kwargs)
        self.user_id = user_id
        self.id = uuid4().hex
        self.expire_at = int(time.time()) + EXPIRATION_DELTA
        self.confirmed = False

    @property
    def expired(self) -> bool:
        return time.time() > self.expire_at

    def force_to_expire(self) -> None:
        if not self.expired:
            self.expire_at = time.time()
            self.save_to_db()

    @classmethod
    def find_by_id(cls, _id: str) -> "ConfirmationModel":
        return cls.query.filter_by(id=_id).first()

    def save_to_db(self) -> None:
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self) -> None:
        db.session.add(self)
        db.session.commit()
