import pytest

from flask import Flask


@pytest.fixture(scope='session')
def app(request):
    """
    Returns session wide application
    """
    app = Flask(__name__)
    app.config['TESTING'] = True

    return app


@pytest.fixture(scope='session')
def client(app):
    """
    Returns session wide Flask test-client
    """
    return app.test_client()
