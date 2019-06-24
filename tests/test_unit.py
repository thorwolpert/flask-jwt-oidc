from flask_jwt_oidc import JwtManager
from flask import Flask
from unittest.mock import patch
import io
import json


PUBLIC_KEYS = {
    "keys": [
        {
            "kid": "flask-jwt-oidc-test-client",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": (
                "AN-fWcpCyE5KPzHDjigLaSUVZI0uYrcGcc40InVtl-rQRDmAh-C2W8H4_Hxh"
                "r5VLc6crsJ2LiJTV_E72S03pzpOOaaYV6-TzAjCou2GYJIXev7f6Hh512PuG"
                "5wyxda_TlBSsI-gvphRTPsKCnPutrbiukCYrnPuWxX5_cES9eStR"
            ),
            "e": "AQAB"
        }
    ]
}

PRIVATE_KEYS = {
    "keys": [
        {
            "kid": "flask-jwt-oidc-test-client",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kty": "RSA",
            "n": (
                "AN-fWcpCyE5KPzHDjigLaSUVZI0uYrcGcc40InVtl-rQRDmAh-C2W8H4_Hxh"
                "r5VLc6crsJ2LiJTV_E72S03pzpOOaaYV6-TzAjCou2GYJIXev7f6Hh512PuG"
                "5wyxda_TlBSsI-gvphRTPsKCnPutrbiukCYrnPuWxX5_cES9eStR"
            ),
            "e": "AQAB",
            "d": (
                "C0G3QGI6OQ6tvbCNYGCqq043YI_8MiBl7C5dqbGZmx1ewdJBhMNJPStuckhs"
                "kURaDwk4-8VBW9SlvcfSJJrnZhgFMjOYSSsBtPGBIMIdM5eSKbenCCjO8Tg0"
                "BUh_xa3CHST1W4RQ5rFXadZ9AeNtaGcWj2acmXNO3DVETXAX3x0"
            ),
            "p": (
                "APXcusFMQNHjh6KVD_hOUIw87lvK13WkDEeeuqAydai9Ig9JKEAAfV94W6Af"
                "tka7tGgE7ulg1vo3eJoLWJ1zvKM"
            ),
            "q": (
                "AOjX3OnPJnk0ZFUQBwhduCweRi37I6DAdLTnhDvcPTrrNWuKPg9uGwHjzFCJ"
                "gKd8KBaDQ0X1rZTZLTqi3peT43s"
            ),
            "dp": (
                "AN9kBoA5o6_Rl9zeqdsIdWFmv4DB5lEqlEnC7HlAP-3oo3jWFO9KQqArQL1V"
                "8w2D4aCd0uJULiC9pCP7aTHvBhc"
            ),
            "dq": (
                "ANtbSY6njfpPploQsF9sU26U0s7MsuLljM1E8uml8bVJE1mNsiu9MgpUvg39"
                "jEu9BtM2tDD7Y51AAIEmIQex1nM"
            ),
            "qi": (
                "XLE5O360x-MhsdFXx8Vwz4304-MJg-oGSJXCK_ZWYOB_FGXFRTfebxCsSYi0"
                "YwJo-oNu96bvZCuMplzRI1liZw"
            )
        }
    ]
}

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXQIBAAKBgQDfn1nKQshOSj8xw44oC2klFWSNLmK3BnHONCJ1bZfq0EQ5gIfg\n"
    "tlvB+Px8Ya+VS3OnK7Cdi4iU1fxO9ktN6c6TjmmmFevk8wIwqLthmCSF3r+3+h4e\n"
    "ddj7hucMsXWv05QUrCPoL6YUUz7Cgpz7ra24rpAmK5z7lsV+f3BEvXkrUQIDAQAB\n"
    "AoGAC0G3QGI6OQ6tvbCNYGCqq043YI/8MiBl7C5dqbGZmx1ewdJBhMNJPStuckhs\n"
    "kURaDwk4+8VBW9SlvcfSJJrnZhgFMjOYSSsBtPGBIMIdM5eSKbenCCjO8Tg0BUh/\n"
    "xa3CHST1W4RQ5rFXadZ9AeNtaGcWj2acmXNO3DVETXAX3x0CQQD13LrBTEDR44ei\n"
    "lQ/4TlCMPO5bytd1pAxHnrqgMnWovSIPSShAAH1feFugH7ZGu7RoBO7pYNb6N3ia\n"
    "C1idc7yjAkEA6Nfc6c8meTRkVRAHCF24LB5GLfsjoMB0tOeEO9w9Ous1a4o+D24b\n"
    "AePMUImAp3woFoNDRfWtlNktOqLel5PjewJBAN9kBoA5o6/Rl9zeqdsIdWFmv4DB\n"
    "5lEqlEnC7HlAP+3oo3jWFO9KQqArQL1V8w2D4aCd0uJULiC9pCP7aTHvBhcCQQDb\n"
    "W0mOp436T6ZaELBfbFNulNLOzLLi5YzNRPLppfG1SRNZjbIrvTIKVL4N/YxLvQbT\n"
    "NrQw+2OdQACBJiEHsdZzAkBcsTk7frTH4yGx0VfHxXDPjfTj4wmD6gZIlcIr9lZg\n"
    "4H8UZcVFN95vEKxJiLRjAmj6g273pu9kK4ymXNEjWWJn\n"
    "-----END RSA PRIVATE KEY-----"
)

ISSUER = "https://example.com/auth/realms/example"

AUDIENCE = "example"

OPENID_CONFIG_URI = f"{ISSUER}/.well-known/openid-configuration"

JWKS_URI = f"{ISSUER}/certs"

ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

def test_init_app_with_test_mode():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_TEST_MODE": True,
        "JWT_OIDC_TEST_AUDIENCE": AUDIENCE,
        "JWT_OIDC_TEST_ISSUER": ISSUER,
        "JWT_OIDC_TEST_KEYS": PUBLIC_KEYS,
        "JWT_OIDC_TEST_PRIVATE_KEY_JWKS": PRIVATE_KEYS,
        "JWT_OIDC_TEST_PRIVATE_KEY_PEM": PEM,
    })

    jwt = JwtManager()
    jwt.init_app(app)

    assert jwt.jwt_oidc_test_mode
    assert jwt.issuer == ISSUER
    assert jwt.jwt_oidc_test_keys == PUBLIC_KEYS
    assert jwt.audience == AUDIENCE
    assert jwt.jwt_oidc_test_private_key_pem == PEM
    assert jwt.algorithms == JwtManager.ALGORITHMS


def test_init_app_with_config_uri():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_WELL_KNOWN_CONFIG": OPENID_CONFIG_URI,
        "JWT_OIDC_AUDIENCE": AUDIENCE,
    })

    jwt = JwtManager()

    fp = io.BytesIO(json.dumps({
        "jwks_uri": JWKS_URI,
        "issuer": ISSUER,
    }).encode("ascii"))
    
    with patch('flask_jwt_oidc.jwt_manager.urlopen') as mock:
        mock.return_value = fp

        jwt.init_app(app)

    assert not jwt.jwt_oidc_test_mode
    assert jwt.issuer == ISSUER
    assert jwt.jwks_uri == JWKS_URI
    assert jwt.audience == AUDIENCE
    assert jwt.algorithms == JwtManager.ALGORITHMS


def test_init_app_with_manual_config():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_JWKS_URI": JWKS_URI,
        "JWT_OIDC_AUDIENCE": AUDIENCE,
        "JWT_OIDC_ISSUER": ISSUER,
    })

    jwt = JwtManager()
    jwt.init_app(app)

    assert not jwt.jwt_oidc_test_mode
    assert jwt.issuer == ISSUER
    assert jwt.jwks_uri == JWKS_URI
    assert jwt.audience == AUDIENCE
    assert jwt.algorithms == JwtManager.ALGORITHMS



def test_init_app_with_algorithms():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_JWKS_URI": JWKS_URI,
        "JWT_OIDC_AUDIENCE": AUDIENCE,
        "JWT_OIDC_ISSUER": ISSUER,
        "JWT_OIDC_ALGORITHMS": ALGORITHMS,
    })

    jwt = JwtManager()
    jwt.init_app(app)

    assert not jwt.jwt_oidc_test_mode
    assert jwt.issuer == ISSUER
    assert jwt.jwks_uri == JWKS_URI
    assert jwt.audience == AUDIENCE
    assert jwt.algorithms == ALGORITHMS



def test_init_app_with_algorithms_as_string():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_JWKS_URI": JWKS_URI,
        "JWT_OIDC_AUDIENCE": AUDIENCE,
        "JWT_OIDC_ISSUER": ISSUER,
        "JWT_OIDC_ALGORITHMS": ",".join(ALGORITHMS),
    })

    jwt = JwtManager()
    jwt.init_app(app)

    assert not jwt.jwt_oidc_test_mode
    assert jwt.issuer == ISSUER
    assert jwt.jwks_uri == JWKS_URI
    assert jwt.audience == AUDIENCE
    assert jwt.algorithms == ALGORITHMS




def test_get_jwks_with_test_mode():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_TEST_MODE": True,
        "JWT_OIDC_TEST_AUDIENCE": AUDIENCE,
        "JWT_OIDC_TEST_ISSUER": ISSUER,
        "JWT_OIDC_TEST_KEYS": PUBLIC_KEYS,
        "JWT_OIDC_TEST_PRIVATE_KEY_JWKS": PRIVATE_KEYS,
        "JWT_OIDC_TEST_PRIVATE_KEY_PEM": PEM,
    })

    jwt = JwtManager(app)

    keys = jwt.get_jwks()

    assert keys == PUBLIC_KEYS


def test_get_jwks():
    app = Flask(__name__)
    app.config.update({
        "JWT_OIDC_JWKS_URI": JWKS_URI,
        "JWT_OIDC_AUDIENCE": AUDIENCE,
        "JWT_OIDC_ISSUER": ISSUER,
    })

    jwt = JwtManager(app)

    fp = io.BytesIO(json.dumps(PUBLIC_KEYS).encode("ascii"))
    
    with patch('flask_jwt_oidc.jwt_manager.urlopen') as mock:
        mock.return_value = fp

        keys = jwt.get_jwks()

    assert keys == PUBLIC_KEYS
