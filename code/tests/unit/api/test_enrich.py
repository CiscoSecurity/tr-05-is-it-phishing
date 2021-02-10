from http import HTTPStatus

from pytest import fixture
from unittest.mock import patch

from .utils import headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@fixture(scope='module')
def invalid_json_type():
    return [{'type': 'strange', 'value': 'cisco.com'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        route, client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "Invalid JSON payload received. "
        "{0: {'value': ['Field may not be blank.']}}"
    )


def test_enrich_call_with_valid_jwt_but_unsupported_type(
        route, client, valid_jwt, invalid_json_type,
        expected_payload_unsupported_type
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json_type)
    assert response.status_code == HTTPStatus.OK
    assert response.json == expected_payload_unsupported_type


@fixture(scope='module')
def valid_json():
    return [{'type': 'url', 'value': 'http://thisisphishing.com'}]


@patch('requests.post')
def test_enrich_call_success(
        mock_request, route, client, valid_jwt, valid_json,
        success_enrich_expected_payload, is_it_phishing_success_response
):
    mock_request.return_value = is_it_phishing_success_response
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    if response.get('data') and response['data'].get('verdicts'):
        for doc in response['data']['verdicts']['docs']:
            assert doc.pop('valid_time')
    if response.get('data') and response['data'].get('judgements'):
        for doc in response['data']['judgements']['docs']:
            assert doc.pop('valid_time')
            assert doc.pop('id')
    assert response == success_enrich_expected_payload


@fixture(scope='module')
def valid_json_multiple():
    return [{'type': 'url', 'value': 'http://thisisphishing.com'},
            {'type': 'url', 'value': 'test'},
            {'type': 'url', 'value': 'http://thisisanotherphishing.com'}]


@patch('requests.post')
def test_enrich_call_with_extended_error_handling(
        mock_request, route, client, valid_jwt, valid_json_multiple,
        success_enrich_expected_payload, is_it_phishing_success_response,
        is_it_phishing_invalid_url_response,
        internal_server_error_expected_payload,
        is_it_phishing_internal_server_error
):
    mock_request.side_effect = [
        is_it_phishing_success_response,
        is_it_phishing_invalid_url_response,
        is_it_phishing_internal_server_error
    ]
    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json_multiple
    )
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    if route != '/refer/observables':
        if response['data'].get('verdicts'):
            for doc in response['data']['verdicts']['docs']:
                assert doc.pop('valid_time')
        if response['data'].get('judgements'):
            for doc in response['data']['judgements']['docs']:
                assert doc.pop('valid_time')
                assert doc.pop('id')
        assert response['errors'] == \
            internal_server_error_expected_payload['errors']
    assert response['data'] == success_enrich_expected_payload['data']


@patch('requests.post')
def test_enrich_with_ssl_error(
        mock_request, route, client, valid_jwt,
        valid_json, is_it_phishing_ssl_exception_mock,
        ssl_error_expected_payload
):

    mock_request.side_effect = is_it_phishing_ssl_exception_mock

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    response = response.get_json()
    assert response == ssl_error_expected_payload
