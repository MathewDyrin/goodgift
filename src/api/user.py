import datetime
import hashlib
import traceback
from flask import request, render_template
from flask_restful import Resource
from flask_jwt_extended import (
    jwt_required,
    jwt_optional,
    get_jwt_identity,
    create_access_token,
    create_refresh_token,
    get_raw_jwt,
    jwt_refresh_token_required
)
from src.extensions import BLACKLIST
from src.models.user import UserModel
from src.models.confirmation import ConfirmationModel
from libs.passhash import PassCrypt
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
            return {"message": response_quote("user_email_taken")}, 400
        password_salt, password_hash = PassCrypt.generate_password_hash(data["password"])
        user = UserModel(
            username=data["username"],
            password_hash=password_hash,
            password_salt=password_salt,
            email=data["email"]
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
        data = request.get_json()
        user = UserModel.find_by_email(data["email"])
        if user and PassCrypt.check_password_hash(user.password_hash, user.password_salt, data["password"]):
            confirmation = user.most_recent_confirmation
            if confirmation and confirmation.confirmed:
                #  в ключ сессии закладывается текущее время сервера во время авторизации.
                user.session_key = hashlib.sha256(str.encode(str(datetime.datetime.now()))).hexdigest()
                user.save_to_db()
                access_token = create_access_token(identity=user.session_key, expires_delta=EXPIRES_DELTA)
                refresh_token = create_refresh_token(identity=user.session_key)
                if user.second_fa_enabled:
                    try:
                        token = hashlib.sha256(str.encode(user.email)).hexdigest()
                        code = EmailSecondFA.generate_2fa_code(token)
                        user.token_2fa = token
                        user.session_key = None
                        user.save_to_db()
                        user.send_email_2fa_code(code)
                        return {"verification_token": token}, 202
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
        jti = get_raw_jwt()["jti"]
        current_user = UserModel.find_by_session_key(get_jwt_identity())
        if current_user:
            current_user.session_key = None
            current_user.save_to_db()
            username = current_user.username
            BLACKLIST.add(jti)
            return {"message": response_quote("user_logged_out").format(username)}, 200
        return {"message": response_quote("code_400")}, 400


class UserPasswordRestoreRequest(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        user = UserModel.find_by_email(data["email"])
        if user:
            try:
                token = hashlib.sha256(str.encode(user.email)).hexdigest()
                code = EmailSecondFA.generate_2fa_code(token)
                user.token_2fa = token
                user.save_to_db()
                user.password_reset_request(code)
                return {"request_token": token}, 200
            except MailGunException as e:
                return {"message": str(e)}, 500
        return {"message": response_quote("user_not_exist")}, 404


class UserPasswordReSetter(Resource):
    @classmethod
    def post(cls, token: str):
        data = request.get_json()
        user = UserModel.find_by_token_2fa(token)
        if user:
            response = EmailSecondFA.check_2fa_code(token, data["code"])
            if response:
                password_salt, password_hash = PassCrypt.generate_password_hash(data["new_password"])
                user.password_salt = password_salt
                user.password_hash = password_hash
                user.token_2fa = None
                user.session_key = None
                user.save_to_db()
                EmailSecondFA.force_revoke_2fa_code(token)
                return {"message": response_quote("user_password_reset")}, 201
            return {"message": response_quote("email2fa_failed")}, 401
        return {"message": response_quote("code_404")}, 404


class TokenRefresher(Resource):
    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        session_key = get_jwt_identity()
        if not UserModel.find_by_session_key(session_key):
            return {"message": response_quote("token_expired_signature")}, 401
        return {
            "access_token": create_access_token(identity=session_key, expires_delta=EXPIRES_DELTA),
            "refresh_token": create_access_token(identity=session_key)
        }, 200


class UserEmail2FA(Resource):
    @classmethod
    def post(cls, token: str):
        data = request.get_json()
        user = UserModel.find_by_token_2fa(token)
        if user:
            response = EmailSecondFA.check_2fa_code(token, data["code"])
            if response:
                session_key = hashlib.sha256(str.encode(str(datetime.datetime.now()))).hexdigest()
                user.session_key = session_key
                user.token_2fa = None
                user.save_to_db()
                EmailSecondFA.force_revoke_2fa_code(token)
                access_token = create_access_token(identity=user.session_key, expires_delta=datetime.timedelta(hours=4))
                return {
                    "access_token": access_token
                }, 200
            return {"message": response_quote("email2fa_failed")}, 401
        return {"message": response_quote("code_404")}, 404


class User(Resource):
    @classmethod
    @jwt_optional
    # TODO: REMAKE WITH SCHEMAS
    def get(cls, _id: int):
        user = UserModel.find_by_id(_id)
        if user:
            return {
                "username": user.username,
                "name": user.name,
                "surname": user.surname,
                "locality": user.locality,
                "profile_pic": user.profile_pic,
                "second_fa_enabled": user.second_fa_enabled,
                "balance": user.balance
               }, 200
        return {"message": response_quote("user_id_not_found").format(_id)}, 404

    @classmethod
    @jwt_required
    # TODO: REMAKE WITH SCHEMAS
    def put(cls, _id: int):
        data = request.get_json()
        current_user = get_jwt_identity()
        user = UserModel.find_by_id(_id)
        if user:
            if user.session_key != current_user:
                return {"message": response_quote("code_401")}, 401
            user.username = data["username"]
            user.name = data["name"]
            user.surname = data["surname"]
            user.locality = data["locality"]
            user.balance = data["balance"]
            user.profile_pic = data["profile_pic"]
            user.session_key = None if not user.second_fa_enabled and data["second_fa_enabled"] else user.session_key
            user.second_fa_enabled = data["second_fa_enabled"]
            user.save_to_db()
            print(user.session_key)
            return {"message": response_quote("user_data_changed")}, 201
        return {"message": response_quote("user_id_not_found").format(_id)}, 404

    @classmethod
    @jwt_required
    def delete(cls, _id: int):
        current_user = get_jwt_identity()
        user = UserModel.find_by_id(_id)
        if user:
            if user.session_key != current_user:
                return {"message": response_quote("code_401")}, 401
            user.delete_from_db()
            return {"message": response_quote("user_deleted")}, 201
        return {"message": response_quote("user_id_not_found").format(_id)}, 404


class UserList(Resource):
    @classmethod
    def get(cls, limit=100):
        return {"users_list": [user.turn_to_json() for user in UserModel.query.limit(limit)]}


# JUST FOR TESTING
class Content(Resource):
    @classmethod
    @jwt_required
    def get(cls):
        current_user = get_jwt_identity()
        user = UserModel.find_by_session_key(current_user)
        if not user:
                return {"message": response_quote("code_401")}, 401
        return f"session key {current_user}"
