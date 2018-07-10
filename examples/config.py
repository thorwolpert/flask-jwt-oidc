from os import environ as env
from dotenv import load_dotenv, find_dotenv


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

class Config(object):

    JWT_OIDC_WELL_KNOWN_CONFIG = env.get('JWT_OIDC_WELL_KNOWN_CONFIG')
    JWT_OIDC_ALGORITHMS = env.get('JWT_OIDC_ALGORITHMS')
    JWT_OIDC_JWKS_URI = env.get('JWT_OIDC_JWKS_URI')
    JWT_OIDC_ISSUER = env.get('JWT_OIDC_ISSUER')
    JWT_OIDC_AUDIENCE = env.get('JWT_OIDC_AUDIENCE')
    JWT_OIDC_CLIENT_SECRET = env.get('JWT_OIDC_CLIENT_SECRET')
