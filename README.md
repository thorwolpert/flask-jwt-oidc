# Flask JWT OIDC

### Simple OIDC JWT extension to protect APIs
This is a fairly simple extension that should require minimal setup for OIDC standard services.

Currently it's testing against Keycloak, but will be adding in example configs and testing for:
- Keycloak
- dex
- Google
- Amazon IAM
- Auth0


### Alternatives
There are some great alternatives that are not so opinionated and provide more support for general JWTs
Check out: [**Flask-JWT-Simple**](https://github.com/vimalloc/flask-jwt-simple) 

### Example(s)
There is one example under
`example/flask_app`
It uses pytest and sets up a dummy JWT to be used in the tests.
### Configuration
Create a .env file,  or OS configmap, shell exports, etc.
```bash
#.env
export JWT_OIDC_WELL_KNOWN_CONFIG="https://KEYCLOAK-SERVICE/auth/realms/REALM-NAME/.well-known/openid-configuration"
export JWT_OIDC_AUDIENCE="keycloak-client"
export JWT_OIDC_CLIENT_SECRET="keycloak-client-secret"
```

Create a config file, that reads in the environment variables:
```python
# config.py

from os import environ as env
from dotenv import load_dotenv, find_dotenv


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

class Config(object):

    JWT_OIDC_WELL_KNOWN_CONFIG = env.get('JWT_OIDC_WELL_KNOWN_CONFIG')
    JWT_OIDC_AUDIENCE = env.get('JWT_OIDC_AUDIENCE')
    JWT_OIDC_CLIENT_SECRET = env.get('JWT_OIDC_CLIENT_SECRET')
```

Create a flask script that to use the JWT services

Note: that roles can be checked as either *decorators* managing access to the function, or as a *function* call that returns True/False for finer grained access control in the body of the function.
```python
# app.py

from flask import Flask, jsonify
from flask_cors import cross_origin
from config import Config
from flask_jwt_oidc import AuthError, JwtManager


app = Flask(__name__)

app.config.from_object(Config)

def get_roles(dict):
    return dict['realm_access']['roles']
app.config['JWT_ROLE_CALLBACK'] = get_roles

jwt = JwtManager(app)

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
    if jwt.validate_roles("names_editor"):
        return jsonify(message="This is a secured endpoint, where roles were examined in the body of the procedure! "
                               "You provided a valid JWT token")

    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)


@app.route("/api/secured-decorated-roles")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"]) # IRL you'd scope this to a real domain
@jwt.requires_roles("names_editor")
def secure_deco_roles():
    """valid access token and assigned roles are required
    """
    return jsonify(message="This is a secured endpoint. "
                           "The roles were checked before entering the body of the procedure! "
                           "You provided a valid JWT token")


if __name__ == "__main__":
    app.run()

```
## Thanks
The following folks have provided help, feedback, PRs, etc:
- Jamie Lennox
- James Hollinger

## TODO
- add tests
- add more examples
- add tests for the OIDC service providers listed above
