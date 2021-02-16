from flask import jsonify


def helper_create_jwt(jwt_manager, roles=[]):
    token_header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "flask-jwt-oidc-test-client"
    }
    claims = {
        "iss": "https://example.localdomain/auth/realms/example",
        "sub": "43e6a245-0bf7-4ccf-9bd0-e7fb85fd18cc",
        "aud": "example",
        "exp": 2539722391,
        "iat": 1539718791,
        "jti": "flask-jwt-oidc-test-support",
        "typ": "Bearer",
        "username": "test-user",
        "realm_access": {
            "roles": [] + roles
        }
    }
    return jwt_manager.create_jwt(claims, token_header)


def test_protected_requires_auth_cookie_with_no_cookie(client, app, jwt):
    message = 'This is a cookie protected end-point'

    @app.route('/cookie-protected')
    @jwt.requires_auth_cookie
    def get():
        return jsonify(message=message)

    rv = client.get('/cookie-protected')
    assert rv.status_code == 401


def test_protected_requires_auth_cookie_with_cookie(client, app, jwt):
    message = 'This is a cookie protected end-point'

    @app.route('/cookie-protected')
    @jwt.requires_auth_cookie
    def get():
        return jsonify(message=message)

    token = helper_create_jwt(jwt)
    client.set_cookie('/', 'oidc-jwt', token)

    rv = client.get('/cookie-protected')
    assert message.encode('utf-8') in rv.data


def test_protected_requires_auth_cookie_with_custom_cookie_name(client, app, jwt):
    message = 'This is a cookie protected end-point'

    @app.route('/cookie-protected')
    @jwt.requires_auth_cookie
    def get():
        return jsonify(message=message)

    # Change the name of cookie from default ('oidc-jwt') and validate the token.
    cookie_name: str = 'custom-jwt-cookie'
    app.config['JWT_OIDC_AUTH_COOKIE_NAME'] = cookie_name

    token = helper_create_jwt(jwt)
    client.set_cookie('/', cookie_name, token)

    rv = client.get('/cookie-protected')
    assert message.encode('utf-8') in rv.data
