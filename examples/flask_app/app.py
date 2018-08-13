
"""Python Flask API with OIDC JWT setup

Minimum config:

    JWT_OIDC_WELL_KNOWN_CONFIG= HTTPS URL to .well_known oidc_config
    JWT_OIDC_AUDIENCE= the OIDC Audience or Client_Id
    JWT_OIDC_CLIENT_SECRET= the OIDC client_secret

    The jwks_uri & issuer URLs are obtained from the .well_known config endpoint
"""

from flask import Flask, jsonify, current_app
from flask_cors import cross_origin
from examples.flask_app.config import Config
# from flask_jwt_oidc import AuthError, JwtManager
from flask_jwt_oidc import JwtManager, AuthError


jwt = JwtManager()


def create_app(config=Config):
    app = Flask(__name__)
    app.config.from_object(config)

    setup_jwt_manager(app, jwt)
    add_routes(app)

    return app


def setup_jwt_manager(app, jwt):
    def get_roles(a_dict):
        return a_dict['realm_access']['roles']
    app.config['JWT_ROLE_CALLBACK'] = get_roles

    jwt.init_app(app)

    return


def add_routes(app):
    @app.route("/api/public")
    @cross_origin(headers=["Content-Type", "Authorization"])
    def public():
        """No auth verification
        """
        return jsonify(message="This is an unprotected endpoint open to the public!")


    @app.route("/api/secure")
    @cross_origin(headers=["Content-Type", "Authorization"])
    @cross_origin(headers=["Access-Control-Allow-Origin", "*"]) # IRL you'd scope this to set domains
    @jwt.requires_auth
    def secure():
        """A Bearer JWT is required to get a response from this endpoint
        """
        return jsonify(message="The is a secured endpoint. You provided a valid Bearer JWT to access it.")


    @app.route("/api/secured-and-roles")
    @cross_origin(headers=["Content-Type", "Authorization"])
    @cross_origin(headers=["Access-Control-Allow-Origin", "*"]) # IRL you'd scope this to a real domain
    @jwt.requires_auth
    def secure_with_roles():
        """valid access token and assigned roles are required
        """
        if jwt.validate_roles(['editor', 'approver']):
            return jsonify(message="This is a secured endpoint, where roles were examined in the body of the procedure! "
                                   "You provided a valid JWT token")

        raise AuthError({
            "code": "Unauthorized",
            "description": "You don't have access to this resource"
        }, 403)


    @app.route("/api/secured-decorated-roles")
    @cross_origin(headers=["Content-Type", "Authorization"])
    @cross_origin(headers=["Access-Control-Allow-Origin", "*"]) # IRL you'd scope this to a real domain
    @jwt.requires_roles(['approver'])
    def secure_deco_roles():
        """valid access token and assigned roles are required
        """
        return jsonify(message="This is a secured endpoint. "
                               "The roles were checked before entering the body of the procedure! "
                               "You provided a valid JWT token")

    return


app = create_app()


if __name__ == "__main__":

    app.run()
