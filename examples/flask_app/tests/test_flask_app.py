from flask import jsonify, g, _request_ctx_stack


def test_public_api(client):
    """
    testing the unprotected URL, this sets a baseline that our basic client connection is working
    :fixture client:
    """
    rv = client.get('/api/public')

    json_msg = 'This is an unprotected endpoint open to the public!'

    assert json_msg.encode('utf-8') in rv.data


def test_public_api_fancy(client):
    """
    fancier test that uses jsonify
    This verifies a basic test that our request processing is inside an active flask context
    :fixture client:
    """
    rv = client.get('/api/public')

    json_msg = jsonify(message='This is an unprotected endpoint open to the public!')

    assert json_msg.data == rv.data


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
        "roles": [
            "editor",
            "approver",
            "viewer",
            "user"
        ]
    }
}


def test_api_secure(client, jwt):
    """
    First test that verifies we have a valid JWT Bearer token
    :fixture client:
    """
    token = jwt.create_jwt(claims, token_header)
    headers = {'Authorization': 'Bearer ' + token}
    rv = client.get('/api/secure', headers=headers)

    json_msg = jsonify(message='The is a secured endpoint. You provided a valid Bearer JWT to access it.')

    assert json_msg.data == rv.data


def test_api_secure_and_role_in_body(client, jwt):
    """
    Testing both a valid token and testing the roles callback within the function body
    :fixture client:
    """
    token = jwt.create_jwt(claims, token_header)
    headers = {'Authorization': 'Bearer ' + token}
    rv = client.get('/api/secure', headers=headers)

    rv = client.get('/api/secured-and-roles', headers=headers)

    json_msg = jsonify(message="This is a secured endpoint, where roles were examined in the body of the procedure! "
                       "You provided a valid JWT token")

    assert json_msg.data == rv.data


def test_api_secure_and_decorate_roles(client, jwt):
    """
    Testing both a valid token and the roles decorator
    :fixture client:
    """
    token = jwt.create_jwt(claims, token_header)
    headers = {'Authorization': 'Bearer ' + token}

    rv = client.get('/api/secured-decorated-roles', headers=headers)

    json_msg = jsonify(message="This is a secured endpoint. "
                               "The roles were checked before entering the body of the procedure! "
                               "You provided a valid JWT token")

    assert json_msg.data == rv.data


def test_api_secure_and_decorate_with_at_least_one_valid_role(client, jwt):
    """
    Testing both a valid token and the roles decorator
    :fixture client:
    """
    token = jwt.create_jwt(claims, token_header)
    headers = {'Authorization': 'Bearer ' + token}

    rv = client.get('/api/secured-decorated-at-least-one-role', headers=headers)

    json_msg = jsonify(message="This is a secured endpoint. "
                               "The roles were checked before entering the body of the procedure! "
                               "You provided a valid JWT token")

    assert json_msg.data == rv.data


def test_current_user_set(app, client, jwt):

    token = jwt.create_jwt(claims, token_header)
    headers = {'Authorization': 'Bearer ' + token}
    rv = client.get('/api/secure', headers=headers)

    assert rv
    assert _request_ctx_stack.top.current_user.get('username') == claims.get('username')
    assert g.jwt_oidc_token_info.get('username') == claims.get('username')


def test_api_cookie_secure(client, jwt):
    """
    First test that verifies we have a valid cookie with jwt
    :fixture client:
    """
    token = jwt.create_jwt(claims, token_header)
    client.set_cookie('/', 'oidc-jwt', token)

    rv = client.get('/api/cookie-secure')

    json_msg = jsonify(message='This is a secured endpoint. You provided a valid cookie in request to access.')

    assert json_msg.data == rv.data
