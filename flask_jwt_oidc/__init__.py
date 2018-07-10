"""Flask-JWT-OIDC

   Is a highly opinionated extension that supports JWR Bearer tokens issued by OIDC compliant servers

   Minimum config:

    JWT_OIDC_WELL_KNOWN_CONFIG= HTTPS URL to .well_known oidc_config
    JWT_OIDC_AUDIENCE= the OIDC Audience or Client_Id
    JWT_OIDC_CLIENT_SECRET= the OIDC client_secret

    JWT_ROLE_CALLBACK is a required callback, that must return a list of roles
    ex:
                def get_roles(dict):
                    return dict['realm_access']['roles']
                app.config['JWT_ROLE_CALLBACK'] = get_roles


    The jwks_uri & issuer URLs are obtained from the .well_known config endpoint

    Optional Configs:

    JWT_OIDC_ALGORITHMS="RS256"

    JWT_OIDC_JWKS_URI (str): an HTTPS to jwks_uri which is an array of valid RSA keys
    JWT_OIDC_ISSUER (str): an HTTPS URL that is the ISS of the token
    JWT_OIDC_AUDIENCE (str): the oidc client audience (sometimes called client_id)
    JWT_OIDC_CLIENT_SECRET (str): the client secret assigned to this audience
    JWT_OIDC_AUTH_ERROR_HANDLER: (fn) to handle raised AuthError

"""
from .exceptions import AuthError
from .jwt_manager import JwtManager