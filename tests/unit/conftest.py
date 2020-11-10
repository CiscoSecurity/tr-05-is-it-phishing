from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock
from requests.exceptions import SSLError

from authlib.jose import jwt
from pytest import fixture

from app import app
from api.errors import INVALID_ARGUMENT


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'key': 'some_key'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


def is_it_phishing_response_mock(status_code, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='function')
def is_it_phishing_health_response_ok():
    return is_it_phishing_response_mock(
        HTTPStatus.OK, payload={
            "status": "PHISHING"
        }
    )


@fixture(scope='function')
def is_it_phishing_internal_server_error():
    return is_it_phishing_response_mock(
        HTTPStatus.INTERNAL_SERVER_ERROR
    )


def expected_payload(route, body):
    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    if route.endswith('/refer/observables'):
        return {'data': []}

    return body


@fixture(scope='session')
def is_it_phishing_ssl_exception_mock(secret_key):
    mock_exception = MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    return SSLError(mock_exception)


@fixture(scope='module')
def ssl_error_expected_payload(route, client):
    if route in ('/observe/observables', '/health'):
        return {
            'errors': [
                {
                    'code': 'unknown',
                    'message': 'Unable to verify SSL certificate: '
                               'Self signed certificate',
                    'type': 'fatal'
                }
            ]
        }

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


@fixture(scope='module')
def internal_server_error_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": "internal server error",
                    "message": "Unexpected response from Is It "
                               "Phishing: Internal Server Error",
                    "type": "fatal"
                }
            ]
        }
    )


@fixture(scope='module')
def invalid_json_expected_payload():
    def _make_message(message):
        return {
            'errors': [
                {
                    'code': INVALID_ARGUMENT,
                    'message': message,
                    'type': 'fatal'
                }
            ]
        }

    return _make_message
