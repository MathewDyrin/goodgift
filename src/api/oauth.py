# import datetime
# import hashlib
# from flask import g
# from flask_restful import Resource
# from flask_jwt_extended import create_access_token, create_refresh_token
# from src.extensions import github
# from src.models.user import UserModel
#
#
# EXPIRES_DELTA = datetime.timedelta(minutes=30)
#
#
# class GithubLogin(Resource):
#     @classmethod
#     def get(cls):
#         return github.authorize(callback="http://localhost:5000/login/oauth/github/authorized")
#
#
# class GithubAuthorize(Resource):
#     @classmethod
#     def get(cls):
#         response = github.authorized_response()
#         g.access_token = response['access_token']
#         github_user = github.get('user')
#         github_username = github_user.data['login']
#
#         user = UserModel.find_by_username(github_username)
#         if not user:
#             user = UserModel(
#                 username=github_username,
#                 password="*********",
#                 email="*********",
#                 sha_private=hashlib.sha256(str.encode(github_username)).hexdigest()
#             )
#             user.save_to_db()
#         access_token = create_access_token(identity=user.sha_private, expires_delta=EXPIRES_DELTA)
#         refresh_token = create_refresh_token(identity=user.sha_private)
#         return {
#             "access_token": access_token,
#             "refresh_token": refresh_token
#         }, 200
