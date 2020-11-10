import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    API_URL = "https://iip.eu.vadesecure.com/api/v2/url"

    REQUEST_JSON = {
        'force': False,
        'smart': True,
        'timeout': 8000
    }

    SAMPLE_PHISHING_URL = 'http://www.thisisaphishingurl.com'

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')
