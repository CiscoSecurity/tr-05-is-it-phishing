import jwt
import json
import requests

from flask import request, jsonify, g
from requests.exceptions import ConnectionError, InvalidURL
from jwt import InvalidSignatureError, InvalidAudienceError, DecodeError
from api.errors import (
    AuthorizationError,
    InvalidArgumentError,
    IsItPhishingSSLError
)

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWK_HOST_MISSING = ('jwks_host is missing in JWT payload. Make sure '
                    'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_public_key(jwks_host, token):
    expected_errors = {
        ConnectionError: WRONG_JWKS_HOST,
        InvalidURL: WRONG_JWKS_HOST,
    }
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint
    """

    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWK_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }
    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}
        ).get('jwks_host')
        assert jwks_host
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        return payload['key']
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def ssl_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.SSLError as error:
            raise IsItPhishingSSLError(error)
    return wrapper


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def append_warning(warning):
    g.errors = [*g.get('errors', []), warning.json]


def jsonify_result():
    result = {'data': {}}

    if g.get('verdicts'):
        result['data']['verdicts'] = format_docs(g.verdicts)
    if g.get('judgements'):
        result['data']['judgements'] = format_docs(g.judgements)

    if g.get('errors'):
        result['errors'] = g.errors
        if not result['data']:
            del result['data']

    return jsonify(result)
