from http import HTTPStatus
import requests

from api.utils import ssl_error_handler
from api.errors import (
    AuthorizationError, UnexpectedIsItPhishingError
)


NOT_CRITICAL_ERRORS = (
    HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND
)


class IsItPhishingClient:
    def __init__(self, key, user_agent, api_url, request_json):
        self.api_url = api_url
        self.headers = {
            'Authorization': f'Bearer {key}',
            'User-Agent': user_agent
        }
        self.request_json = request_json

    @ssl_error_handler
    def get_is_it_phishing_response(self, observable):
        data = {
            'url': observable,
            **self.request_json
        }

        try:
            response = requests.post(
                self.api_url,
                json=data,
                headers=self.headers
            )
        except UnicodeEncodeError:
            raise AuthorizationError()

        if response.ok:
            return response.json()
        elif response.status_code == HTTPStatus.UNAUTHORIZED:
            raise AuthorizationError()
        elif response.status_code in NOT_CRITICAL_ERRORS:
            return {}

        raise UnexpectedIsItPhishingError(response.status_code)
