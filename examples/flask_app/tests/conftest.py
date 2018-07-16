import pytest

from flask import  Flask, current_app
from flask_jwt_oidc import AuthError, JwtManager

from examples.flask_app.app import create_app, jwt as _jwt
from examples.flask_app.config import TestConfig


@pytest.fixture(scope="session")
def app(request):
    """
    Returns session-wide application.
    """
    app = create_app(TestConfig)

    return app


@pytest.fixture(scope="session")
def jwt(app):
    """
    Returns session-wide jwt manager
    """
    return _jwt


@pytest.fixture(scope="session")
def client(app):
    """
    Returns session-wide Flask test client.
    """
    with app.test_client() as c:
        yield c
