from flask import request, current_app, _request_ctx_stack, jsonify
from six.moves.urllib.request import urlopen
from jose import jwt
from functools import wraps

import json

from .exceptions import AuthError


class JwtManager(object):

    ALGORITHMS = ["RS256"]

    def __init__(self, app=None):

        # These are all set in the init_app function, but are listed here for easy reference
        self.app = app
        self.well_known_config = None
        self.well_known_obj_cache = None
        self.algorithms = JwtManager.ALGORITHMS
        self.jwks_uri = None
        self.issuer = None
        self.audience = None
        self.client_secret = None

        self.jwt_oidc_test_mode = False
        self.jwt_oidc_test_keys = None

        if app is not None:
            self.init_app(app)


    def init_app(self, app):
        """initializze this extension

        if the config['JWT_OIDC_WELL_KNOWN_CONFIG'] is set, then try to load the JWKS_URI & ISSUER from that
        If it is not set
        attempt to load the JWKS_URI and ISSUE from the application config

        Required settings to function:
        WELL_KNOWN_CONFIG (optional) is this is set, the JWKS_URI & ISSUER will be loaded from there
        JWKS_URI: the endpoint defined for the jwks_keys
        ISSUER: the endpoint for the issuer of the tokens
        ALGORITHMS: only RS256 is supported
        AUDIENCE: the oidc audience (or API_IDENTIFIER)
        CLIENT_SECRET: the shared secret / key assigned to the client (audience)
        """
        self.jwt_oidc_test_mode = app.config.get('JWT_OIDC_TEST_MODE', None)
        #
        ## CHECK IF WE"RE RUNNING IN TEST_MODE!!
        #
        if self.jwt_oidc_test_mode:
            app.logger.error('JWT MANAGER running in test mode, using locally defined certs & tokens')

            self.issuer = app.config.get('JWT_OIDC_TEST_ISSUER', 'localhost.localdomain')
            self.jwt_oidc_test_keys = app.config.get('JWT_OIDC_TEST_KEYS', None)
            self.audience = app.config.get('JWT_OIDC_TEST_AUDIENCE', None)
            self.client_secret = app.config.get('JWT_OIDC_TEST_CLIENT_SECRET', None)
            self.jwt_oidc_test_private_key_pem = app.config.get('JWT_OIDC_TEST_PRIVATE_KEY_PEM', None)

            if self.jwt_oidc_test_keys:
                app.logger.debug('local key being used: {}'.format(self.jwt_oidc_test_keys))
            else:
                app.logger.error('Attempting to run JWT Manager with no local key assigned')
                raise Exception('Attempting to run JWT Manager with no local key assigned')

        else:

            self.algorithms = [app.config.get('JWT_OIDC_ALGORITHMS', 'RS256')]

            # If the WELL_KNOWN_CONFIG is set, then go fetch the JWKS & ISSUER
            self.well_known_config = app.config.get('JWT_OIDC_WELL_KNOWN_CONFIG', None)
            if self.well_known_config:
                # try to get the jwks & issuer from the well known config
                jurl = urlopen(self.well_known_config)
                self.well_known_obj_cache = json.loads(jurl.read().decode("utf-8"))

                self.jwks_uri = self.well_known_obj_cache['jwks_uri']
                self.issuer = self.well_known_obj_cache['issuer']
            else:

                self.jwks_uri = app.config.get('JWT_OIDC_JWKS_URI', None)
                self.issuer = app.config.get('JWT_OIDC_ISSUER', None)

            self.audience = app.config.get('JWT_OIDC_AUDIENCE', None)
            self.client_secret = app.config.get('JWT_OIDC_CLIENT_SECRET', None)

        app.logger.error('JWKS_URI: {}'.format(self.jwks_uri))
        app.logger.error('ISSUER: {}'.format(self.issuer))
        app.logger.error('ALGORITHMS: {}'.format(self.algorithms))
        app.logger.error('AUDIENCE: {}'.format(self.audience))
        app.logger.error('CLIENT_SECRET: {}'.format(self.client_secret))
        app.logger.error('JWT_OIDC_TEST_MODE: {}'.format(self.jwt_oidc_test_mode))
        app.logger.error('JWT_OIDC_TEST_KEYS: {}'.format(self.jwt_oidc_test_keys))
        app.logger.error('JWT_OIDC_TEST_KEYS: {}'.format(type(self.jwt_oidc_test_keys)))

        # set the auth error handler
        auth_err_handler = app.config.get('JWT_OIDC_AUTH_ERROR_HANDLER', JwtManager.handle_auth_error)
        app.register_error_handler(AuthError, auth_err_handler)

        app.teardown_appcontext(self.teardown)

    def teardown(self, exception):
        pass
        # ctx = _app_ctx_stack.top
        # if hasattr(ctx, 'cached object'):

    @staticmethod
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response

    def get_token_auth_header(self):
        """Obtains the access token from the Authorization Header
        """

        auth = request.headers.get("Authorization", None)
        if not auth:
            raise AuthError({"code": "authorization_header_missing",
                        "description": "Authorization header is expected"}
                            ,401)

        parts = auth.split()

        if parts[0].lower() != "bearer":
            raise AuthError({"code": "invalid_header",
                        "description": "Authorization header must start with Bearer"}
                            ,401)

        elif len(parts) < 2:
            raise AuthError({"code": "invalid_header",
                        "description": "Token not found after Bearer"}
                            ,401)

        elif len(parts) > 2:
            raise AuthError({"code": "invalid_header",
                        "description": "Authorization header is an invalid token structure"}
                            ,401)

        return parts[1]


    def validate_roles(self, required_roles):
        """Checks that the listed roles are in the token
           using the registered callback
        Args:
            required_roles (str): Comma separated list of required roles
            JWT_ROLE_CALLBACK (fn): The callback added to the Flask configuration
        """
        token = self.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        roles_in_token = current_app.config['JWT_ROLE_CALLBACK'](unverified_claims)
        if [role for role in roles_in_token if role in required_roles]:
            return True
        return False


    def requires_roles(self, required_roles):
        """Checks that the listed roles are in the token
           using the registered callback
        Args:
            required_roles (str): Comma separated list of required roles
            JWT_ROLE_CALLBACK (fn): The callback added to the Flask configuration
        """
        def decorated(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                self.requires_auth(f)(*args, **kwargs)
                if self.validate_roles(required_roles):
                    return f(*args, **kwargs)
                raise AuthError({"code": "missing_required_roles",
                                 "description":
                                     "Missing the role(s) required to access this endpoint"}, 401)
            return wrapper
        return decorated


    def requires_auth(self, f):
        """Validates the Bearer Token
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            token = self.get_token_auth_header()

            jwks = self.get_jwks()
            try:
                unverified_header = jwt.get_unverified_header(token)
            except jwt.JWTError:
                raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
            if unverified_header["alg"] == "HS256":
                raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
            current_app.logger.debug('unverified_header: {}'.format(unverified_header))
            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
            if rsa_key:
                try:
                    payload = jwt.decode(
                        token,
                        rsa_key,
                        algorithms=self.algorithms,
                        audience=self.audience,
                        issuer=self.issuer
                )
                except jwt.ExpiredSignatureError:
                    raise AuthError({"code": "token_expired",
                                "description": "token has expired"}, 401)
                except jwt.JWTClaimsError:
                    raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401)
                except Exception:
                    raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

                _request_ctx_stack.top.current_user = payload
                return f(*args, **kwargs)
            raise AuthError({"code": "invalid_header",
                        "description": "Unable to find jwks key referenced in token"}, 401)
        return decorated

    def get_jwks(self):

        if self.jwt_oidc_test_mode:
            jwks = self.jwt_oidc_test_keys
        else:
            jsonurl = urlopen(self.jwks_uri)
            jwks = json.loads(jsonurl.read().decode("utf-8"))

        return jwks

    def create_jwt(self, claims):
        header={
            "alg": "RS256",
            "typ": "JWT",
            "kid": "flask-jwt-oidc-test-client"
        }
        token = jwt.encode(claims,self.jwt_oidc_test_private_key_pem, headers=header, algorithm='RS256')
        return token

