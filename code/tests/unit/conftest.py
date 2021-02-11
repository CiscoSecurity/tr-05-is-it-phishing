import jwt

from app import app
from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock, patch
from api.errors import INVALID_ARGUMENT
from requests.exceptions import SSLError
from tests.unit.mock_keys_for_tests import PRIVATE_KEY
from tests.unit.mock_keys_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


@fixture(scope='function')
def valid_json():
    return [{'type': 'ip', 'value': 'cisco.com'}]


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='some_key',
            jwks_host='b4046e54-5629-4da3-bdad-0a732f81a3cf.mock.pstmn.io',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='function')
def mock_request():
    with patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='function')
def mock_response_data():
    def _set_data(status_code=None,
                  payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT):
        mock_data = MagicMock()

        mock_data.status_code = status_code if status_code else HTTPStatus.OK

        if payload:
            mock_data.json = lambda: payload

        return mock_data
    return _set_data


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
def is_it_phishing_ssl_exception_mock():
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
def is_it_phishing_invalid_url_response():
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


@fixture(scope='module')
def expected_payload_unsupported_type(route):
    payload_to_route_match = {
        '/refer/observables': {'data': []},
        '/deliberate/observables': {'data': {}},
        '/observe/observables': {'data': {}}
    }
    return payload_to_route_match[route]
