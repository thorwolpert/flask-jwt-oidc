import pytest
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


def test_protected_requires_auth(client, app, jwt):

    message = 'This is an unprotected end-point'

    @app.route('/protected')
    @jwt.requires_auth
    def get():
        return jsonify(message=message)

    token = helper_create_jwt(jwt)
    headers = {'Authorization': 'Bearer ' + token}
    rv = client.get('/protected', headers=headers)

    assert message.encode('utf-8') in rv.data


decorator_role_test_data = [
    ('single_role_pass', ['editor'], ['editor'], 200),
    ('single_role_fail', ['wrong_role'], ['editor'], 401),
    ('multi_role_pass', ['editor', 'viewer'], ['editor', 'viewer'], 200),
    ('multi_role_fail', ['editor', 'wrong_role'], ['editor', 'viewer'], 401),
]


@pytest.mark.parametrize("test_name, jwt_role, endpoint_role, expected_code", decorator_role_test_data)
def test_protected_auth_and_role(client, app, jwt, test_name, jwt_role, endpoint_role, expected_code):

    message = 'This is an unprotected end-point'

    @app.route('/protected')
    @jwt.requires_roles(endpoint_role)
    def get():
        return jsonify(message=message)

    token = helper_create_jwt(jwt, jwt_role)
    headers = {'Authorization': 'Bearer ' + token}
    rv = client.get('/protected', headers=headers)

    if expected_code is 200:
        assert message.encode('utf-8') in rv.data

    assert rv.status_code == expected_code
