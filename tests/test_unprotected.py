from flask import jsonify


def test_unprotected(client, app):

    message='This is an unprotected end-point'

    @app.route('/unprotected')
    def get():
        return jsonify(message=message)

    rv = client.get('/unprotected')

    print ('test is', rv.data)

    assert message.encode('utf-8') in rv.data
