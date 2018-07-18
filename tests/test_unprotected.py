from flask import jsonify


def test_unprotected(client, app):

    message='This is an unprotected end-point'

    @app.route('/unprotected')
    def public():
        return jsonify(message=message)

    rv = client.get('/unprotected')

    assert ('"message":"'+message+'"').encode('utf-8') in rv.data
