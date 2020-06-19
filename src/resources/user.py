import datetime
import hashlib
import traceback
from flask import request
from flask_restful import Resource
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    create_access_token,
    create_refresh_token,
    get_raw_jwt,
    jwt_refresh_token_required
)
from src.extensions import b_crypt, BLACKLIST
from src.models.user import UserModel
from src.models.confirmation import ConfirmationModel
from libs.mail.mailgun import MailGunException
from libs.serving import response_quote
from libs.f2auth.email_f2auth import EmailSecondFA

'''
|   NAME      |     PATH       |   HTTP VERB     |            PURPOSE                   |
|----------   |----------------|-----------------|--------------------------------------|
| Add User    | /users         |      GET        | Get list of the users                |
| Get User    | /users/<int:id>|      GET        | Get a user with id                   |
| New         | /users/register|      POST       | Register a user {username, password} |
'''

"""
CONSTANTS 
"""

EXPIRES_DELTA = datetime.timedelta(minutes=30)


class UserRegister(Resource):
    # TODO: remake with schemas
    @classmethod
    def post(cls):
        data = request.get_json()
        if UserModel.find_by_email(data["email"]):
            return {"message": response_quote("user_email_taken")}, 400  # TODO:
        user = UserModel(
            username=data["username"],
            password=b_crypt.generate_password_hash(data["password"]).decode("utf-8"),
            email=data["email"],
            sha_private=hashlib.sha256(str.encode(data["email"])).hexdigest()
        )
        try:
            user.save_to_db()
            confirmation = ConfirmationModel(user.id)
            confirmation.save_to_db()
            user.confirm()
            return {"message": response_quote("user_been_created")}, 201
        except MailGunException as e:
            user.delete_from_db()   # rollback
            return {"message": str(e)}, 500
        except:
            traceback.print_exc()
            user.delete_from_db()
            return {"message": response_quote("operation_fatal_error")}, 500


class UserLogin(Resource):
    #  TODO: remake with schemas
    @classmethod
    def post(cls):
        """
        :return: access_token, refresh_token
        """
        data = request.get_json()
        user = UserModel.find_by_email(data["email"])
        if user and b_crypt.check_password_hash(user.password, data["password"]):
            confirmation = user.most_recent_confirmation
            if confirmation and confirmation.confirmed:
                access_token = create_access_token(identity=user.sha_private, expires_delta=EXPIRES_DELTA)
                refresh_token = create_refresh_token(identity=user.sha_private)
                if user.second_fa_enabled:
                    try:
                        token = hashlib.sha256(str.encode(user.sha_private)).hexdigest()
                        code = EmailSecondFA.generate_2fa_code(token)  # еще подумать над этим функционалом
                        user.token_2fa = token
                        user.save_to_db()
                        user.send_email_2fa_code(code)
                        return {"verification_token": token}
                    except MailGunException as e:
                        return {"message": str(e)}
                return {"access_token": access_token, "refresh_token": refresh_token}, 201
            else:
                return {"message": response_quote("user_not_confirmed").format(user.username)}, 400
        else:
            return {"message": response_quote("user_invalid_credentials")}, 401


class UserLogout(Resource):
    @classmethod
    @jwt_required
    def post(cls):
        # TODO: NOT PERFECT
        jti = get_raw_jwt()["jti"]
        username = UserModel.find_by_sha_token(get_jwt_identity()).username
        BLACKLIST.add(jti)
        return {"message": response_quote("user_logged_out").format(username)}, 200


class TokenRefresher(Resource):
    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        user_id = get_jwt_identity()
        return {"access_token": create_access_token(identity=user_id, expires_delta=EXPIRES_DELTA)}, 201


class UserEmail2FA(Resource):
    @classmethod
    def post(cls, token: str):
        data = request.get_json()
        user = UserModel.find_by_token_2fa(token)
        if user:
            response = EmailSecondFA.check_2fa_code(token, data["code"])
            if response:
                access_token = create_access_token(identity=user.sha_private, expires_delta=EXPIRES_DELTA)
                refresh_token = create_refresh_token(identity=user.sha_private)
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }, 200
            return {"message": response_quote("email2fa_failed")}, 400
        return {"message": response_quote("user_not_exist")}, 404


class User(Resource):
    @classmethod
    # @jwt_required  --- make auth
    # TODO: REMAKE WITH SCHEMAS
    def get(cls, _id: int):
        user = UserModel.find_by_id(_id)
        if user:
            return {"username": user.username, "email": user.email, "balance": user.balance}, 200
        return {"message": response_quote("user_id_not_found").format(_id)}, 404

    @classmethod
    @jwt_required
    # TODO: REMAKE WITH SCHEMAS
    def put(cls, _id: int):
        data = request.get_json()
        current_user = get_jwt_identity()
        user = UserModel.find_by_id(_id)
        if user:
            if user.sha_private != current_user:
                return {"message": response_quote("code_401")}, 401
            user.username = data["username"]
            user.name = data["name"]
            user.surname = data["surname"]
            user.locality = data["locality"]
            user.balance = data["balance"]
            user.profile_pic = data["profile_pic"]
            user.second_fa_enabled = data["second_fa_enabled"]
            user.save_to_db()
            return {"message": response_quote("user_data_changed")}, 201
        return {"message": response_quote("user_id_not_found").format(_id)}, 404

    @classmethod
    @jwt_required
    def delete(cls, _id: int):
        current_user = get_jwt_identity()
        user = UserModel.find_by_id(_id)
        if user:
            if user.sha_private != current_user:
                return {"message": response_quote("code_401")}, 401
            user.delete_from_db()
            # TODO: удалить все jwt токены.
            return {"message": response_quote("user_deleted")}, 201
        return {"message": response_quote("user_id_not_found").format(_id)}, 404


class UserList(Resource):
    @classmethod
    def get(cls, limit=100):
        return {"users_list": [user.turn_to_json() for user in UserModel.query.limit(limit)]}


class Content(Resource):
    @classmethod
    @jwt_required
    def get(cls):
        return "secret content"
