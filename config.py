import os
from datetime import timedelta

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

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    ENTITY_RELEVANCE_PERIOD = timedelta(days=7)

    STATUS_MAPPING = {
        'UNKNOWN': {
            "disposition": 5,
            "disposition_name": "Unknown",
        },
        'TIMEOUT': {
            "disposition": 5,
            "disposition_name": "Unknown",
        },
        'NOT_EXPLORED': {
            "disposition": 5,
            "disposition_name": "Unknown",
        },
        'SPAM': {
            "disposition": 3,
            "disposition_name": "Suspicious",
        },
        'PHISHING': {
            "disposition": 2,
            "disposition_name": "Malicious",
        }
    }

    CTIM_SCHEMA_VERSION = '1.0.22'

    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'source': 'IsItPhishing',
        'confidence': 'High',
        'priority': 85,
        'schema_version': CTIM_SCHEMA_VERSION,
    }

    SEVERITY_MAPPING = {
        'UNKNOWN': 'Unknown',
        'TIMEOUT': 'Unknown',
        'NOT_EXPLORED': 'Unknown',
        'SPAM': 'Medium',
        'PHISHING': 'High'
    }
