from flask import jsonify

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


# headers = {'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEeEJ2b2dvUG1Lc0dFZnlkdnRVandDUF9sV18wd1V2b1NzV3F6NVFtRlFFIn0.eyJqdGkiOiJhMTgwNzYzYy1kYTFkLTQyZmUtOTcwNi1iMDRkZDA1MjU3MTciLCJleHAiOjE1MzE3MjYwNDMsIm5iZiI6MCwiaWF0IjoxNTMxNzI0MjQzLCJpc3MiOiJodHRwczovL2Rldi1zc28ucGF0aGZpbmRlci5nb3YuYmMuY2EvYXV0aC9yZWFsbXMvbmVzdCIsImF1ZCI6Im5hbWV4LURFViIsInN1YiI6IjQzZTZhMjQ1LTBiZjctNGNjZi05YmQwLWU3ZmI4NWZkMThjYyIsInR5cCI6IkJlYXJlciIsImF6cCI6Im5hbWV4LURFViIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjE5ZmVmNjc5LTZiNTQtNGRmNC05M2VmLTIzYjg4YTMzZWE5NyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsibmFtZXNfZWRpdG9yIiwibmFtZXNfYXBwcm92ZXIiLCJuYW1lc192aWV3ZXIiLCJ1bWFfYXV0aG9yaXphdGlvbiIsInVzZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJuYW1lIjoicG9zdCBtYW4iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJwb3N0bWFuIiwiZ2l2ZW5fbmFtZSI6InBvc3QiLCJmYW1pbHlfbmFtZSI6Im1hbiIsImVtYWlsIjoiIn0.nWoJpSszwlVQlW1P4Di9HtQ9kqwbCZtdnzB7wjo199Bar9lUVJ_xKJFVkqUJlvNtLoUyRoiv-TGDqDUe3CmeHAfLwwgkOHW6xOW6YQxaJz4M6VYOTxgQ5xiPLAxhIwPBfXURf2fS9r7u8IgUM1yNf6tMRe7HUSExjn7zwkcvVmqS5QzlWja59eAY087sHbD1QehX-hmBHoKp4QEU0IHseuahdHrpMPQdDKkfwKALqbaL9tyGUb6ekKpskebt2wgBh6hu636bCfishhBUl69tJnWqlJ0CCXEIftks1DshWkbqDSstHU9CXl72ZCD9_NUQhqbjNCyfFZxygF_C-vLq6Q'
#                }

claims = {
            "iss": "https://dev-sso.pathfinder.gov.bc.ca/auth/realms/nest",
            "sub": "43e6a245-0bf7-4ccf-9bd0-e7fb85fd18cc",
            "aud": "namex-DEV",
            "exp": 21531718745,
            "iat": 1531718745,
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

def test_api_secure (client, jwt):
    """
    First test that verifies we have a valid JWT Bearer token
    :fixture client:
    """
    token = jwt.create_jwt(claims)
    headers = {'Authorization': 'Bearer ' + token}
    rv = client.get('/api/secure', headers=headers)

    json_msg = jsonify(message='The is a secured endpoint. You provided a valid Bearer JWT to access it.')

    print(rv.data)

    assert json_msg.data == rv.data


def test_api_secure_and_role_in_body (client, jwt):
    """
    Testing both a valid token and testing the roles callback within the function body
    :fixture client:
    """
    token = jwt.create_jwt(claims)
    headers = {'Authorization': 'Bearer ' + token}

    rv = client.get('/api/secured-and-roles', headers=headers)

    json_msg = jsonify(message="This is a secured endpoint, where roles were examined in the body of the procedure! "
                                   "You provided a valid JWT token")

    assert json_msg.data == rv.data


def test_api_secure_and_decorate_roles (client, jwt):
    """
    Testing both a valid token and the roles decorator
    :fixture client:
    """
    token = jwt.create_jwt(claims)
    headers = {'Authorization': 'Bearer ' + token}

    rv = client.get('/api/secured-decorated-roles', headers=headers)

    json_msg = jsonify(message="This is a secured endpoint. "
                               "The roles were checked before entering the body of the procedure! "
                               "You provided a valid JWT token")

    assert json_msg.data == rv.data

