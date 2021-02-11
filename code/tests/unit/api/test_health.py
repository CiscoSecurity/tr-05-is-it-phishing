from pytest import fixture
from .utils import headers
from http import HTTPStatus
from unittest.mock import patch


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('requests.post')
def test_health_call_success(
        mock_request, is_it_phishing_success_response,
        route, client, valid_jwt
):
    mock_request.return_value = is_it_phishing_success_response
    response = client.post(route, headers=headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK


@patch('requests.post')
def test_health_call_failure(
        mock_request, route, client, valid_jwt,
        is_it_phishing_internal_server_error,
        internal_server_error_expected_payload
):
    mock_request.return_value = is_it_phishing_internal_server_error
    response = client.post(route, headers=headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == internal_server_error_expected_payload


@patch('requests.post')
def test_health_with_ssl_error(
        mock_request, route, client, valid_jwt,
        is_it_phishing_ssl_exception_mock,
        ssl_error_expected_payload
):

    mock_request.side_effect = is_it_phishing_ssl_exception_mock

    response = client.post(
        route, headers=headers(valid_jwt())
    )

    assert response.status_code == HTTPStatus.OK

    response = response.get_json()
    assert response == ssl_error_expected_payload
