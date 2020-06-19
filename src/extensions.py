import os
from flask import g
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_httpauth import HTTPBasicAuth
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

db = SQLAlchemy()
jwt = JWTManager()
auth = HTTPBasicAuth()
ma = Marshmallow()
b_crypt = Bcrypt()
BLACKLIST = set()


"""
    / ** ** ** ** ** ** ** ** / / / JWT SETTINGS / ** ** ** ** ** ** ** ** /
"""


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token["jti"] in BLACKLIST


"""
    / ** ** ** ** ** ** ** ** / / / OAuth SETTINGS / ** ** ** ** ** ** ** ** / 
"""

# oauth = OAuth()
# load_dotenv()
# github = oauth.remote_app(
#     'github',
#     consumer_key=os.getenv("GITHUB_CONSUMER_KEY"),
#     consumer_secret=os.getenv("GITHUB_CONSUMER_SECRET"),
#     request_token_params={"scope": "user:email"},
#     base_url="https://api.github.com/",
#     request_token_url=None,
#     access_token_method="POST",
#     access_token_url="https://github.com/login/oauth/access_token",
#     authorize_url="https://github.com/login/oauth/authorize"
# )
#
#
# @github.tokengetter
# def get_github_token():
#     if "access_token" in g:
#         return g.access_token
