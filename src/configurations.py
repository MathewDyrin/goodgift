import os


class DevelopmentConfig:
    SECRET_KEY = 'secret-jose'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///data.db'
    JWT_SECRET_KEY = 'super-secret'
    JWT_BLACKLIST_ENABLED = True
    DEBUG = True

    CONFIG_NAME = 'Development'


class TestingConfig:
    pass


class ProductionConfig:
    SECRET_KEY = 'secret-jose'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'postgres://lubucfvs:1grmik2DE6ZOgIHzvBY0tZ17EXNA__l1@ruby.db.elephantsql.com:5432/lubucfvs'
    JWT_SECRET_KEY = 'super-secret'
    JWT_BLACKLIST_ENABLED = True
    # TODO: DEBUG FALSE
    DEBUG = True

    CONFIG_NAME = 'Production'
