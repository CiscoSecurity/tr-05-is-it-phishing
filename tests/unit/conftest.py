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
def is_it_phishing_success_response():
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
    if route.endswith('/refer/observables'):
        return {'data': []}

    return body


@fixture(scope='module')
def success_observe_body():
    return {
            'data': {
                'verdicts': {
                    'count': 1,
                    'docs': [
                        {'disposition': 2,
                         'disposition_name': 'Malicious',
                         'observable': {
                             'type': 'url',
                             'value': 'http://thisisphishing.com'
                         },
                         'type': 'verdict'
                         }
                    ]
                },
                'judgements': {
                    'count': 1,
                    'docs': [
                        {'confidence': 'High',
                         'disposition': 2,
                         'disposition_name': 'Malicious',
                         'observable': {
                             'type': 'url',
                             'value': 'http://thisisphishing.com'
                         },
                         'priority': 85,
                         'schema_version': '1.0.22',
                         'severity': 'High',
                         'source': 'IsItPhishing',
                         'type': 'judgement',
                         }
                    ]
                }
            }
    }


@fixture(scope='module')
def success_deliberate_body():
    return {
        'data': {
            'verdicts': {
                'count': 1,
                'docs': [
                    {'disposition': 2,
                     'disposition_name': 'Malicious',
                     'observable': {
                         'type': 'url',
                         'value': 'http://thisisphishing.com'
                     },
                     'type': 'verdict'
                     }
                ]
            }
        }
    }


@fixture(scope='module')
def success_enrich_expected_payload(
        route, success_deliberate_body,
        success_observe_body
):
    payload_to_route_match = {
        '/deliberate/observables': success_deliberate_body,
        '/refer/observables': {'data': []},
        '/observe/observables': success_observe_body
    }
    return payload_to_route_match[route]


@fixture(scope='session')
def is_it_phishing_ssl_exception_mock(secret_key):
    mock_exception = MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    return SSLError(mock_exception)


@fixture(scope='module')
def ssl_error_expected_payload(route, client):
    if route != '/refer/observables':
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

    return {'data': []}


@fixture(scope='session')
def is_it_phishing_invalid_url_response(secret_key):
    return is_it_phishing_response_mock(
        HTTPStatus.BAD_REQUEST
    )


@fixture(scope='module')
def internal_server_error_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": "internal server error",
                    "message": "Unexpected response from "
                               "IsItPhishing: Internal Server Error",
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
