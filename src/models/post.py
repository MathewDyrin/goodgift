from src.extensions import db


class RequestModel(db.Model):

    __tablename__ = "requests"

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    theme = db.Column(db.String(80), nullable=False)
    body = db.Column(db.String(190), nullable=False)
    creator = db.relationship(
        "UserModel",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    executor = db.relationship(
        "UserModel",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    status = db.Column(db.Integer, nullable=False)

    @classmethod
    def find_by_id(cls, _id: int) -> "RequestModel":
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def find_by_theme(cls, theme: str) -> "RequestModel":
        return cls.query.filter_by(theme=theme).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from(self):
        db.session.delete(self)
        db.session.commit()