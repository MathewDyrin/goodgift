import os


class DevelopmentConfig:
    SECRET_KEY = 'secret-jose'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///data.db'
    JWT_SECRET_KEY = 'super-secret'
    JWT_BLACKLIST_ENABLED = True
    DEBUG = True


class TestingConfig:
    pass


class ProductionConfig:
    SECRET_KEY = 'secret-jose'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'postgres://fsollwoh:VG-oDpKT5YzYUc6nbTYtjVKH5U0JW32u@balarama.db.elephantsql.com:5432/fsollwoh'
    JWT_SECRET_KEY = 'super-secret'
    JWT_BLACKLIST_ENABLED = True
    DEBUG = False
